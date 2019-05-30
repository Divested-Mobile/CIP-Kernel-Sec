#!/usr/bin/python3

# Copyright 2017-2018 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

# Report issues affecting each stable branch.

import argparse
import subprocess

import kernel_sec.branch
import kernel_sec.issue
import kernel_sec.version


def main(git_repo, remote_map,
         only_fixed_upstream, include_ignored, *branch_names):
    if branch_names:
        # Support stable release strings as shorthand for stable branches
        branches = [kernel_sec.branch.get_base_ver_stable_branch(name)
                    if name[0].isdigit()
                    else kernel_sec.branch.get_stable_branch(name)
                    for name in branch_names]
    else:
        branches = kernel_sec.branch.get_live_branches()
        if only_fixed_upstream:
            branches = [branch for branch in branches
                        if branch['short_name'] != 'mainline']

    branches.sort(key=kernel_sec.branch.get_sort_key)

    c_b_map = kernel_sec.branch.CommitBranchMap(git_repo, remote_map,
                                                branches)

    branch_issues = {}
    issues = set(kernel_sec.issue.get_list())

    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)
        ignore = issue.get('ignore', {})
        fixed = issue.get('fixed-by', {})

        # Should this issue be ignored?
        if (not include_ignored and ignore.get('all')) or \
           (only_fixed_upstream and fixed.get('mainline', 'never') == 'never'):
            continue

        for branch in branches:
            branch_name = branch['short_name']

            # Should this issue be ignored for this branch?
            if not include_ignored and ignore.get(branch_name):
                continue

            if kernel_sec.issue.affects_branch(
                    issue, branch, c_b_map.is_commit_in_branch):
                branch_issues.setdefault(branch_name, []).append(cve_id)

    for branch in branches:
        branch_name = branch['short_name']
        print('%s:' % branch_name,
              *sorted(branch_issues.get(branch_name, []),
                      key=kernel_sec.issue.get_id_sort_key))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Report unfixed CVEs in Linux kernel branches.')
    parser.add_argument('--git-repo',
                        dest='git_repo', default='../kernel',
                        help=('git repository from which to read commit logs '
                              '(default: ../kernel)'),
                        metavar='DIRECTORY')
    parser.add_argument('--remote-name',
                        dest='remote_name', action='append', default=[],
                        help='git remote name mappings, e.g. stable:korg-stable',
                        metavar='NAME=OTHER-NAME')
    parser.add_argument('--mainline-remote',
                        dest='mainline_remote_name',
                        help="git remote name to use instead of 'torvalds'",
                        metavar='OTHER-NAME')
    parser.add_argument('--stable-remote',
                        dest='stable_remote_name',
                        help="git remote name to use instead of 'stable'",
                        metavar='OTHER-NAME')
    parser.add_argument('--only-fixed-upstream',
                        action='store_true',
                        help='only report issues fixed in mainline')
    parser.add_argument('--include-ignored',
                        action='store_true',
                        help='include issues that have been marked as ignored')
    parser.add_argument('branches',
                        nargs='*',
                        help=('specific branch to report on '
                              '(default: all active branches)'),
                        metavar='BRANCH')
    args = parser.parse_args()
    remote_map = kernel_sec.branch.make_remote_map(
        args.remote_name,
        mainline=args.mainline_remote_name,
        stable=args.stable_remote_name)
    main(args.git_repo, remote_map,
         args.only_fixed_upstream, args.include_ignored, *args.branches)
