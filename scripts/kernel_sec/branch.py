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
    return 'linux-%s.y' % base_ver


def get_stable_branch_base_ver(branch_name):
    match = _STABLE_BRANCH_RE.match(branch_name)
    return match and match.group(1)


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

        # Convert current version to branch name
        match = re.match(r'(\d+\.\d+)\.\d+$', version)
        if not match:
            raise ValueError('failed to parse stable version %r' % version)

        branches.append('linux-%s.y' % match.group(1))

    return branches


def get_live_stable_branches():
    try:
        with open('import/branches.yml') as f:
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
    with open('import/branches.yml', 'w') as f:
        yaml.safe_dump(branches, f)
    return branches


def get_sort_key(branch):
    if branch == 'mainline':
        return [1000000]
    base_ver = get_stable_branch_base_ver(branch)
    assert base_ver is not None
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
    def __init__(self, git_repo, mainline_remote_name, branch_names):
        # Generate sort key for each branch
        self._branch_sort_key = {
            branch: get_sort_key(branch) for branch in branch_names
        }

        # Generate sort key for each commit
        self._commit_sort_key = {}
        start = None
        for branch in sorted(branch_names, key=get_sort_key):
            if branch == 'mainline':
                end = '%s/master' % mainline_remote_name
            else:
                base_ver = get_stable_branch_base_ver(branch)
                assert base_ver is not None
                end = 'v' + base_ver
            for commit in _get_commits(git_repo, end, start):
                self._commit_sort_key[commit] = self._branch_sort_key[branch]
            start = end

    def is_commit_in_branch(self, commit, branch):
        return commit in self._commit_sort_key and \
            self._commit_sort_key[commit] <= self._branch_sort_key[branch]
