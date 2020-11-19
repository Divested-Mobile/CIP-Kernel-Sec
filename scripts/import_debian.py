#!/usr/bin/python3

# Copyright 2017,2020 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

# Import information from Debian's kernel-sec repository.  The format is
# not documented but is based on Debian's variant of RFC822. See
# active/00boilerplate and scripts/filter-active.py in that repository.
#
# May need "pip3 install python-debian"

from debian import deb822
from enum import Enum
import glob
import itertools
import os.path
import re
import shutil
import subprocess
import sys

import kernel_sec.branch
import kernel_sec.issue


IMPORT_DIR = 'import/debian'

LINE_BREAK_RE = re.compile(r'\n\s*')
COMMA_SEP_RE = re.compile(r',\s*')
BRANCH_RE = re.compile(
    r'^(?:(?P<mainline>upstream)'
    r'|(?P<base_ver>[\d.]+)-(?:upstream-stable|(?P<debian>\w+-security)))$')
COMMENT_RE = re.compile(r'^(\w+)>\s+(.*)$')
STATUS_RE = re.compile(r'\s*(?P<state>\S*)'
                       r'(?:\s*\((?P<version>(\S*,\s*)*\S*\s*)\))?'
                       r'(?:\s*\[(?P<changerefs>(\S*,\s*)*\S*)\s*\])?'
                       r'(?:\s*"(?P<reason>.+)")?'
                       r',?')


class BranchFormat(Enum):
    STANDARD = 1
    PATCH_QUEUE = 2


# Match sequence of decimal digits (sorted numerically) or any other
# single character
DPKG_VERSION_PART_RE = re.compile(r'\d+|.')


# Compare two dpkg version strings.  This makes no attempt to detect
# invalid version strings.
def dpkg_version_cmp(left, right):
    def version_parts(ver):
        # Add any implicit epoch
        if ':' not in ver:
            ver = '0:' + ver

        for part in DPKG_VERSION_PART_RE.findall(ver):
            # ~ sorts before anything, including empty string
            if part == '~':
                yield (0,)
            # Decimal digits are sorted numerically, and before any
            # other characters except ~
            if part.isdigit():
                yield (1, int(part))
            # Letters are sorted lexically, after digits
            if part.isalpha():
                yield (2, part)
            # Remaining characters are sorted lexically, after letters
            yield (3, part)

    for lpart, rpart in itertools.zip_longest(version_parts(left),
                                              version_parts(right),
                                              # empty string sorts like 0
                                              fillvalue=(1, 0)):
        if lpart != rpart:
            return -1 if lpart < rpart else 1
    return 0


def bug_url(ref):
    try:
        bug_nr = int(ref)
    except ValueError:
        # Not a number: should be a URL already
        return ref
    else:
        # Just a number: return a Debian bug tracker URL
        return 'https://bugs.debian.org/%d' % bug_nr


def load_debian_issue(f, branches):
    deb_issue = deb822.Deb822(f)
    issue = {}

    issue['description'] = deb_issue['Description']

    references = \
        [ref
         for ref in LINE_BREAK_RE.split(deb_issue['References'].strip())
         if ref] + \
        [bug_url(ref)
         for ref in LINE_BREAK_RE.split(deb_issue['Bugs'].strip())
         if ref]
    if references:
        issue['references'] = references

    # Group and join comment lines by name
    comments = {}
    for line in LINE_BREAK_RE.split(deb_issue['Notes'].strip()):
        if not line:
            continue
        match = COMMENT_RE.match(line)
        if match:
            name = 'debian/' + match.group(1)
            rest = match.group(2)
        else:
            name = 'debian'
            rest = line
        comments.setdefault(name, []).append(rest)
    if comments:
        issue['comments'] = dict((name, '\n'.join(lines))
                                 for (name, lines) in comments.items())

    def get_fixes(branch_name, branch_format, match):
        if branch_format == BranchFormat.STANDARD:
            if match.group('changerefs'):
                hashes = [
                    ref_name
                    for ref_name
                    in COMMA_SEP_RE.split(match.group('changerefs'))
                    if kernel_sec.issue.change_is_git_hash(ref_name)
                ]
                if hashes:
                    return hashes
        else:
            assert branch_format == BranchFormat.PATCH_QUEUE
            is_debian = branch_name.startswith('debian/')
            state = match.group('state')

            if is_debian:
                if state == 'released':
                    version = match.group('version')
                    if version is None or ',' in version or '-' not in version:
                        return None
                    ref_name = 'debian/' + version.replace('~', '_')
                else:
                    assert state == 'pending'
                    ref_name = branch_name[7:]
            else:
                ref_name = 'master'

            if match.group('changerefs'):
                assert branch_format == BranchFormat.PATCH_QUEUE
                patches = COMMA_SEP_RE.split(match.group('changerefs'))
                if patches:
                    return ['patch:%s:%s' % (ref_name, file_name)
                            for file_name in patches]
            elif is_debian and state == 'released':
                # Fixed in this version but without any changes listed.
                # Probably fixed by importing a newer upstream.
                return ['version:' + ref_name]

        return None

    # Branch status
    for key in deb_issue:
        # Parse the branch name and determine format of the branch
        # dependent on state
        match = BRANCH_RE.match(key)
        if not match:
            continue
        base_ver = match.group('base_ver')
        if match.group('mainline'):
            branch_format = {
                'pending':  BranchFormat.STANDARD,
                'released': BranchFormat.STANDARD,
            }
            branch_name = 'mainline'
        elif not match.group('debian'):
            branch_format = {
                'pending':  BranchFormat.PATCH_QUEUE,
                'released': BranchFormat.STANDARD,
            }
            branch_name = 'stable/' + base_ver
        else:
            branch_format = {
                'pending':  BranchFormat.PATCH_QUEUE,
                'released': BranchFormat.PATCH_QUEUE,
            }
            branch_name = 'debian/' + match.group('debian')
        if branch_name not in branches:
            continue

        # For mainline, fixes may span multiple releases
        for match in STATUS_RE.finditer(deb_issue[key]):
            state = match.group('state')
            if state in ['pending', 'released']:
                fixes = get_fixes(branch_name, branch_format[state], match)
                if fixes:
                    issue.setdefault('fixed-by', {}).setdefault(branch_name, []).extend(fixes)
            # However, there will be only one "ignored" entry
            if state == 'ignored' and match.group('reason'):
                issue.setdefault('ignore', {})[branch_name] = match.group('reason')

    # Fill in status for Debian stable branches fixed before the
    # Debian branch point.  These will only be explicitly marked as
    # fixed in sid, though they may have a free-form comment
    # explaining why the stable branch wasn't affected.
    if 'sid' in deb_issue:
        match = STATUS_RE.match(deb_issue['sid'])
        version = match and match.group('version')
        if match \
           and match.group('state') == 'released' \
           and version and ',' not in version:
            fixes = get_fixes('debian/sid', BranchFormat.PATCH_QUEUE, match)
            if fixes:
                for branch_name, branch in branches.items():
                    if branch_name.startswith('debian/') \
                       and branch_name not in issue.get('fixed-by', {}) \
                       and dpkg_version_cmp(
                           version, branch['debian_branch_point']) <= 0:
                        issue.setdefault('fixed-by', {})[branch_name] = fixes

    return issue


def main():
    branches = {
        branch['short_name']: branch
        for branch in kernel_sec.branch.get_live_branches(
                kernel_sec.branch.get_remotes([]))
    }

    # Remove obsolete Subversion working directory
    if os.path.isdir(IMPORT_DIR + '/.svn'):
        shutil.rmtree(IMPORT_DIR)

    # Create/update Git repository
    os.makedirs(IMPORT_DIR, 0o777, exist_ok=True)
    if os.path.isdir(IMPORT_DIR + '/.git'):
        subprocess.check_call(['git', 'pull'], cwd=IMPORT_DIR)
    else:
        subprocess.check_call(
            ['git', 'clone',
             'https://salsa.debian.org/kernel-team/kernel-sec.git', '.'],
            cwd=IMPORT_DIR)

    our_issues = set(kernel_sec.issue.get_list())
    their_issues = dict((os.path.basename(name), name) for name in
                        glob.glob(IMPORT_DIR + '/active/CVE-*'))

    their_issues = dict((os.path.basename(name), name) for name in
                        glob.glob(IMPORT_DIR + '/retired/CVE-*'))

    # Also look at retired issues that we already track, but not the
    # huge number of historical ones
    for cve_id in our_issues:
        if cve_id not in their_issues:
            retired_name = IMPORT_DIR + '/retired/' + cve_id
            if os.path.exists(retired_name):
                their_issues[cve_id] = retired_name

    for cve_id in their_issues:
        their_filename = their_issues[cve_id]
        with open(their_filename) as f:
            try:
                theirs = load_debian_issue(f, branches)
            except (KeyError, ValueError, UnicodeDecodeError):
                print('Failed to parse %s' % their_filename, file=sys.stderr)
                continue

        if cve_id not in our_issues:
            # Copy theirs
            ours = theirs
        else:
            # Check that it's good to start with, then merge into ours
            ours = kernel_sec.issue.load(cve_id)
            kernel_sec.issue.validate(ours)
            if not kernel_sec.issue.merge_into(ours, theirs):
                continue

        try:
            kernel_sec.issue.validate(ours)
        except ValueError as e:
            print('%s: %s' % (their_filename, e), file=sys.stderr)
            continue

        kernel_sec.issue.save(cve_id, ours)


if __name__ == '__main__':
    main()
