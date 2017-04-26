#!/usr/bin/python3

# Copyright 2017 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

# Report issues affecting each stable branch.

import io
import re
import subprocess
import sys

import kernel_sec.branch, kernel_sec.issue, kernel_sec.version

def get_commits(git_repo, end, start=None):
    if start:
        list_expr = '%s..%s' % (start, end)
    else:
        list_expr = end

    list_proc = subprocess.Popen(['git', 'rev-list', list_expr],
                                 cwd=git_repo, stdout=subprocess.PIPE)
    for line in io.TextIOWrapper(list_proc.stdout):
        yield line.rstrip('\n')

# Pad last part of CVE ID to 6 digits so string comparison keeps working
def pad_cve_id(cve_id):
    return re.sub(r'-(\d+)$', lambda m: '-%06d' % int(m.group(1)), cve_id)

def main(git_repo='../kernel', mainline_remote_name='torvalds',
         stable_remote_name='stable', *branch_names):
    if branch_names:
        # Support stable release strings as shorthand for stable branches
        branch_names = [kernel_sec.branch.get_base_ver_stable_branch(name)
                        if name[0].isdigit() else name
                        for name in branch_names]
    else:
        branch_names = kernel_sec.branch.get_live_stable_branches(
                           git_repo, stable_remote_name) \
                       + ['mainline']

    # Generate sort key for each branch
    branch_sort_key = {}
    for branch in branch_names:
        if branch == 'mainline':
            branch_sort_key[branch] = [1000000]
        else:
            base_ver = kernel_sec.branch.get_stable_branch_base_ver(branch)
            assert base_ver is not None
            branch_sort_key[branch] = kernel_sec.version.get_sort_key(base_ver)

    branch_names.sort(key=(lambda branch: branch_sort_key[branch]))

    # Generate sort key for each commit
    commit_sort_key = {}
    start = None
    for branch in branch_names:
        if branch == 'mainline':
            end = '%s/master' % mainline_remote_name
        else:
            base_ver = kernel_sec.branch.get_stable_branch_base_ver(branch)
            assert base_ver is not None
            end = 'v' + base_ver
        for commit in get_commits(git_repo, end, start):
            commit_sort_key[commit] = branch_sort_key[branch]
        start = end

    branch_issues = {}
    issues = set(kernel_sec.issue.get_list())

    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)

        for branch in branch_names:
            # If it was not introduced on this branch, and was introduced on
            # mainline after the branch point, branch is not affected
            introduced = issue.get('introduced-by')
            if introduced:
                if introduced.get('mainline') == 'never' and \
                   (branch == 'mainline' or branch not in introduced):
                    continue
                if branch not in introduced:
                    for commit in introduced['mainline']:
                        if commit in commit_sort_key \
                           and commit_sort_key[commit] <= branch_sort_key[branch]:
                            break
                    else:
                        continue

            # If it was fixed on this branch, or fixed on mainline before
            # the branch point, branch is not affected
            fixed = issue.get('fixed-by')
            if fixed:
                if fixed.get(branch, 'never') != 'never':
                    continue
                if fixed.get('mainline', 'never') != 'never':
                    for commit in fixed['mainline']:
                        if commit not in commit_sort_key \
                           or commit_sort_key[commit] > branch_sort_key[branch]:
                            break
                    else:
                        continue

            branch_issues.setdefault(branch, []).append(cve_id)

    for branch in branch_names:
        print('%s:' % branch, *sorted(branch_issues.get(branch, []), key=pad_cve_id))

if __name__ == '__main__':
    main(*sys.argv[1:])
