# Copyright 2006 Kirill Simonov <xi@resolvent.net>
# Copyright 2017-2018,2020 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import datetime
import glob
import os.path
import re
import yaml
import yaml.dumper
import yaml.loader


# Only SHA-1 for now
_GIT_HASH_RE = re.compile(r'^[0-9a-f]{40}$')


def change_is_git_hash(change):
    return _GIT_HASH_RE.match(change) is not None


def change_is_patch(change):
    return change.startswith('patch:')


def change_patch_info(change):
    if not change_is_patch(change):
        raise ValueError('change string does not name a patch')
    return change[6:].split(':')


def change_is_version(change):
    return change.startswith('version:')


def change_version_tag(change):
    if not change_is_version(change):
        raise ValueError('change string does not name an version')
    return change[8:]


def _validate_string(name, value):
    if type(value) is str:
        return
    raise ValueError('%s must be a string' % name)


def _validate_datetime(name, value):
    if type(value) is datetime.datetime:
        return
    raise ValueError('%s must be an ISO8601 date and time' % name)


def _validate_sequence_string(name, value):
    if type(value) is list:
        for entry in value:
            if type(entry) is not str:
                break
        else:
            return
    raise ValueError('%s must be a sequence of strings' % name)


def _validate_mapping_string(name, value):
    if type(value) is dict:
        for v in value.values():
            if type(v) is not str:
                break
        else:
            return
    raise ValueError('%s must be a mapping to strings' % name)


def _validate_mapping_changes(name, value):
    if type(value) is dict:
        for changes in value.values():
            if changes == 'never':
                continue
            if type(changes) is not list:
                break
            for entry in changes:
                if type(entry) is not str \
                   or not (change_is_git_hash(entry) \
                           or change_is_patch(entry) \
                           or change_is_version(entry)):
                    break  # to outer break
            else:
                continue
            break  # to top level
        else:
            return
    raise ValueError('%s must be a mapping of branch names to changes' %
                     name)


def _validate_hashmapping_string(name, value):
    if type(value) is dict:
        for h, v in value.items():
            if type(h) is not str or not change_is_git_hash(h):
                break
            if type(v) is not str:
                break
        else:
            return
    raise ValueError('%s must be a mapping from git hashes to strings' %
                     name)


_ALL_FIELDS = [
    ('description',     _validate_string),
    ('advisory',        _validate_string),
    ('references',      _validate_sequence_string),
    ('aliases',         _validate_sequence_string),
    ('comments',        _validate_mapping_string),
    ('reporters',       _validate_sequence_string),
    ('embargo-end',     _validate_datetime),
    ('introduced-by',   _validate_mapping_changes),
    ('fixed-by',        _validate_mapping_changes),
    ('fix-depends-on',  _validate_hashmapping_string),
    ('ignore',          _validate_mapping_string),
    ('tests',           _validate_sequence_string)
]
_FIELD_VALIDATOR = dict(_ALL_FIELDS)
_FIELD_ORDER = dict((name, i) for i, (name, _) in enumerate(_ALL_FIELDS))
_REQUIRED_FIELDS = ['description']


def validate(issue):
    for name in _REQUIRED_FIELDS:
        if name not in issue:
            raise ValueError('required field "%s" is missing' % name)

    for name, value in issue.items():
        try:
            validator = _FIELD_VALIDATOR[name]
        except KeyError:
            raise ValueError('field "%s" is unknown' % name)
        else:
            validator(name, value)


def merge_into(ours, theirs):
    changed = False

    def merge_list(field_name):
        nonlocal changed
        if field_name in theirs:
            our_list = ours.setdefault(field_name, [])
            for item in theirs[field_name]:
                if item not in our_list:
                    our_list.append(item)
                    changed = True

    def merge_commit_lists(field_name):
        nonlocal changed
        if field_name in theirs:
            our_dict = ours.setdefault(field_name, {})
            for branch, changes in theirs[field_name].items():
                our_changes = our_dict.setdefault(branch, [])
                # Only update if they agree with what we already have
                # or they replace all patches with commits
                if our_changes != 'never':
                    if set(changes) > set(our_changes):
                        for change in changes:
                            if change not in our_changes:
                                our_changes.append(change)
                                changed = True
                    elif len(changes) == len(our_changes) \
                         and all(change_is_git_hash(change)
                                 for change in changes) \
                         and all(change_is_patch(change)
                                 for change in our_changes):
                        our_changes[:] = changes
                        changed = True

    # Don't attempt to merge description.  As it is a mandatory field
    # we must already have a description.

    merge_list('references')

    if 'comments' in theirs:
        our_comments = ours.setdefault('comments', {})
        for name, comment in theirs['comments'].items():
            # All imported comments should have names qualified in
            # some way so that it's safe to overwrite existing
            # comments with the same name.
            if our_comments.get(name) != comment:
                our_comments[name] = comment
                changed = True

    merge_list('reporters')
    merge_commit_lists('introduced-by')
    merge_commit_lists('fixed-by')

    if 'ignore' in theirs:
        our_ignore = ours.setdefault('ignore', {})
        if 'all' not in our_ignore:
            for name, reason in theirs['ignore'].items():
                if name not in our_ignore:
                    our_ignore[name] = reason
                    changed = True

    return changed


class _IssueDumper(yaml.dumper.SafeDumper):
    # Write strings as UTF-8, not ASCII with escapes
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.allow_unicode = True

    def represent(self, data):
        self.__root = data
        try:
            return super().represent(data)
        finally:
            del self.__root

    # ISO 8601 specifies 'T' to separate date & time, but for some reason
    # PyYAML uses ' ' by default
    def represent_datetime(self, data):
        return self.represent_scalar('tag:yaml.org,2002:timestamp',
                                     data.isoformat())

    # Use literal format if there are literal newlines, as this is much more
    # readable
    def represent_str(self, data):
        return self.represent_scalar('tag:yaml.org,2002:str', data,
                                     style=('|' if '\n' in data else None))

    def represent_mapping(self, tag, mapping, flow_style=None):
        # Always use block style
        node = super().represent_mapping(tag, mapping, False)

        # Sort top-level fields into preferred order
        if mapping is self.__root:
            node.value.sort(
                key=(lambda child: _FIELD_ORDER.get(child[0].value, 100)))

        return node

    def represent_sequence(self, tag, sequence, flow_style=True):
        # Use block style for top-level fields
        for child in self.__root.values():
            if sequence is child:
                flow_style = False

        return super().represent_sequence(tag, sequence, flow_style)


_IssueDumper.add_representer(datetime.datetime,
                             _IssueDumper.represent_datetime)
_IssueDumper.add_representer(str, _IssueDumper.represent_str)


class _IssueLoader(yaml.loader.SafeLoader):
    # Keep timezone information instead of adjusting the timestamp and then
    # discarding it.
    def construct_yaml_timestamp(self, node):
        value = self.construct_scalar(node)
        match = self.timestamp_regexp.match(value)
        values = match.groupdict()
        year = int(values['year'])
        month = int(values['month'])
        day = int(values['day'])
        if not values['hour']:
            return datetime.date(year, month, day)
        hour = int(values['hour'])
        minute = int(values['minute'])
        second = int(values['second'])
        fraction = 0
        if values['fraction']:
            fraction = values['fraction'][:6]
            while len(fraction) < 6:
                fraction += '0'
            fraction = int(fraction)
        if values['tz_sign']:
            tz_hour = int(values['tz_hour'])
            tz_minute = int(values['tz_minute'] or 0)
            delta = datetime.timedelta(hours=tz_hour, minutes=tz_minute)
            if values['tz_sign'] == '-':
                delta = -delta
            tzinfo = datetime.timezone(delta)
        elif values['tz'] == 'Z':
            tzinfo = datetime.timezone.utc
        else:
            tzinfo = None
        return datetime.datetime(year, month, day, hour, minute, second,
                                 fraction, tzinfo)


_IssueLoader.add_constructor('tag:yaml.org,2002:timestamp',
                             _IssueLoader.construct_yaml_timestamp)


def load_filename(name):
    with open(name, 'r', encoding='utf-8') as f:
        return yaml.load(f, Loader=_IssueLoader)


def save_filename(name, issue):
    with open(name, 'w', encoding='utf-8') as f:
        yaml.dump(issue, f, Dumper=_IssueDumper)


def get_list():
    return [os.path.basename(name)[:-4]
            for name in glob.glob('issues/CVE-*.yml')]


def get_filename(cve_id):
    return 'issues/%s.yml' % cve_id


def load(cve_id):
    return load_filename(get_filename(cve_id))


def save(cve_id, issue):
    save_filename(get_filename(cve_id), issue)


# Match the "arbitrary digits" after the year
_cve_id_arbdig_re = re.compile(r'-(\d+)$')


# Pad "arbitrary digits" to 7 digits so string comparison works
def get_id_sort_key(cve_id):
    return _cve_id_arbdig_re.sub(lambda m: '-%07d' % int(m.group(1)), cve_id)


ISSUE_STATUS_NOT_AFFECTED = 'not affected'
ISSUE_STATUS_NOT_FIXED = 'not fixed'
ISSUE_STATUS_FIXED = 'fixed'

def status_on_branch(issue, branch, is_commit_in_branch):
    branch_name = branch['short_name']

    # If it was not introduced on this branch, and was introduced on
    # mainline after the branch point, branch is not affected
    introduced = issue.get('introduced-by')
    if introduced:
        if introduced.get('mainline') == 'never' and \
           (branch_name == 'mainline' or branch_name not in introduced):
            return ISSUE_STATUS_NOT_AFFECTED
        if branch_name not in introduced:
            for commit in introduced['mainline']:
                if is_commit_in_branch(commit, branch):
                    break
            else:
                return ISSUE_STATUS_NOT_AFFECTED

    # If it was fixed on this branch, or fixed on mainline before
    # the branch point, branch is not affected
    fixed = issue.get('fixed-by', {})
    if fixed:
        if fixed.get(branch_name, 'never') != 'never':
            return ISSUE_STATUS_NOT_AFFECTED
        if fixed.get('mainline', 'never') != 'never':
            for commit in fixed['mainline']:
                if not is_commit_in_branch(commit, branch):
                    break
            else:
                return ISSUE_STATUS_FIXED

    return ISSUE_STATUS_NOT_FIXED

def affects_branch(issue, branch, is_commit_in_branch):
    status = status_on_branch(issue, branch, is_commit_in_branch)

    return status == ISSUE_STATUS_NOT_FIXED
