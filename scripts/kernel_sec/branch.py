# Copyright 2017-2018 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import io
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
import warnings

import html5lib
import yaml

from . import version


_STABLE_BRANCH_RE = re.compile(r'^linux-([\d.]+)\.y$')


def get_base_ver_stable_branch(base_ver):
    branch_name = 'linux-%s.y' % base_ver
    return {
        'short_name': branch_name,
        'git_remote': 'stable',
        'git_name': branch_name,
        'base_ver': base_ver
        }


def get_stable_branch(branch_name):
    match = _STABLE_BRANCH_RE.match(branch_name)
    return match and get_base_ver_stable_branch(match.group(1))


def _extract_live_stable_branches(doc):
    xhtml_ns = 'http://www.w3.org/1999/xhtml'
    ns = {'html': xhtml_ns}
    cell_tags = ['{%s}td' % xhtml_ns, '{%s}th' % xhtml_ns]

    tables = doc.findall(".//html:table[@id='releases']", ns)
    if len(tables) == 0:
        raise ValueError('no releases table found')
    if len(tables) > 1:
        raise ValueError('multiple releases tables found')

    branches = []

    for row in tables[0].findall(".//html:tr", ns):
        row_text = []

        # Get text of each cell in the row
        for cell in row:
            if cell.tag not in cell_tags:
                raise ValueError('unexpected element %s found in releases' %
                                 cell.tag)
            row_text.append("".join(cell.itertext()))

        # Extract branch type, current version, EOL flag
        branch_type, version, eol = None, None, None
        if len(row_text) >= 2:
            branch_type = row_text[0].rstrip(':')
            match = re.match(r'([^ ]+)( \[EOL\])?$', row_text[1])
            if match:
                version = match.group(1)
                eol = match.group(2) is not None
        if branch_type not in ['mainline', 'stable', 'longterm', 'linux-next'] \
           or version is None:
            raise ValueError('failed to parse releases row text %r' % row_text)

        # Filter out irrelevant branches
        if branch_type not in ['stable', 'longterm'] or eol:
            continue

        # Convert current version to base version
        match = re.match(r'(\d+\.\d+)\.\d+$', version)
        if not match:
            raise ValueError('failed to parse stable version %r' % version)

        branches.append(get_base_ver_stable_branch(match.group(1)))

    return branches


def _get_live_stable_branches():
    try:
        with open('import/stable_branches.yml') as f:
            branches = yaml.safe_load(f)
            cache_time = os.stat(f.fileno()).st_mtime
    except IOError:
        branches = None
        cache_time = None

    # Use the cache if it's less than a day old
    if cache_time and time.time() - cache_time < 86400:
        return branches

    # Try to fetch and parse releases table
    try:
        with urllib.request.urlopen('https://www.kernel.org') as resp:
            doc = html5lib.parse(resp.read())
        branches = _extract_live_stable_branches(doc)
    except (urllib.error.URLError, ValueError) as e:
        # If we have a cached version, use it but warn
        if branches:
            warnings.warn(str(e), RuntimeWarning)
            return branches
        raise

    os.makedirs('import', 0o777, exist_ok=True)
    with open('import/stable_branches.yml', 'w') as f:
        yaml.safe_dump(branches, f)
    return branches


def _get_configured_branches():
    try:
        with open('conf/branches.yml') as f:
            return yaml.safe_load(f)
    except IOError:
        return []


def get_live_branches():
    branches = _get_live_stable_branches()
    branches.extend(_get_configured_branches())
    branches.append({
        'short_name': 'mainline',
        'git_remote': 'torvalds',
        'git_name': 'master'
        })
    return branches


def get_sort_key(branch):
    try:
        base_ver = branch['base_ver']
    except KeyError:
        return [1000000]
    return version.get_sort_key(base_ver)


def _get_commits(git_repo, end, start=None):
    if start:
        list_expr = '%s..%s' % (start, end)
    else:
        list_expr = end

    list_proc = subprocess.Popen(['git', 'rev-list', list_expr],
                                 cwd=git_repo, stdout=subprocess.PIPE)
    for line in io.TextIOWrapper(list_proc.stdout):
        yield line.rstrip('\n')


class CommitBranchMap:
    def __init__(self, git_repo, remotes, branches):
        # Generate sort key for each branch
        self._branch_sort_key = {
            branch['short_name']: get_sort_key(branch) for branch in branches
        }

        # Generate sort key for each commit
        self._commit_sort_key = {}
        start = None
        for branch in sorted(branches, key=get_sort_key):
            branch_name = branch['short_name']
            if branch_name == 'mainline':
                end = '%s/%s' % (remotes[branch['git_remote']]['git_name'],
                                 branch['git_name'])
            else:
                end = 'v' + branch['base_ver']
            for commit in _get_commits(git_repo, end, start):
                self._commit_sort_key[commit] \
                    = self._branch_sort_key[branch_name]
            start = end

    def is_commit_in_branch(self, commit, branch):
        branch_name = branch['short_name']
        return commit in self._commit_sort_key and \
            self._commit_sort_key[commit] <= self._branch_sort_key[branch_name]


class RemoteMap(dict):
    # Default to identity mapping for anything not explicitly mapped
    def __getitem__(self, key):
        value = self.setdefault(key, {})
        if 'git_name' not in value:
            value['git_name'] = key
        return value


# Create a RemoteMap based on command-line arguments
def get_remotes(mappings, mainline=None, stable=None):
    remotes = RemoteMap()
    for mapping in mappings:
        left, right = arg.split(':', 1)
        remotes[left]['git_name'] = right
    if mainline:
        remotes['torvalds']['git_name'] = mainline
    if stable:
        remotes['stable']['git_name'] = stable
    return remotes
