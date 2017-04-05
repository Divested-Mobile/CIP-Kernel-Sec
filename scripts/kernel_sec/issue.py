import datetime
import glob
import os.path
import re

# Only SHA-1 for now
_GIT_HASH_RE = re.compile(r'^[0-9a-f]{40}$')
def is_git_hash(s):
    return _GIT_HASH_RE.match(s) is not None

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

def _validate_mapping_sequence_hash(name, value):
    if type(value) is dict:
        for seq in value.values():
            if type(seq) is not list:
                break
            for entry in seq:
                if type(entry) is not str or not is_git_hash(entry):
                    break # to outer break
            else:
                continue
            break # to top level
        else:
            return
    raise ValueError('%s must be a mapping to sequences of git hashes' %
                     name)

def _validate_hashmapping_string(name, value):
    if type(value) is dict:
        for h, v in value.items():
            if type(h) is not str or not is_git_hash(h):
                break
            if type(v) is not str:
                break
        else:
            return
    raise ValueError('%s must be a mapping from git hashes to strings' %
                     name)

_ALL_FIELDS = {
    'description': _validate_string,
    'advisory': _validate_string,
    'references': _validate_sequence_string,
    'aliases': _validate_sequence_string,
    'comments': _validate_mapping_string,
    'reporters': _validate_sequence_string,
    'embargo-end': _validate_datetime,
    'introduced-by': _validate_mapping_sequence_hash,
    'fixed-by': _validate_mapping_sequence_hash,
    'fix-depends-on': _validate_hashmapping_string,
    'tests': _validate_sequence_string
}
_REQUIRED_FIELDS = ['description']

def validate(issue):
    for name in _REQUIRED_FIELDS:
        if name not in issue:
            raise ValueError('required field "%s" is missing' % name)

    for name, value in issue.items():
        try:
            validator = _ALL_FIELDS[name]
        except KeyError:
            raise ValueError('field "%s" is unknown' % name)
        else:
            validator(name, value)

def get_list():
    return [(os.path.basename(name)[:-4], name) for name in
            glob.glob('issues/CVE-*.yml')]
