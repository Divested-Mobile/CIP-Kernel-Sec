#!/usr/bin/python3

# Copyright 2017 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

# Fill in introduced-by or fixed-by for stable branches that have
# corresponding commits for all the mainline commits.

import argparse
import io
import re
import subprocess
import sys

import kernel_sec.branch
import kernel_sec.issue


BACKPORT_COMMIT_RE = re.compile(
    r'^(?:' r'commit (%s) upstream\.'
    r'|'    r'\[ Upstream commit (%s) \]'
    r'|'    r'\(cherry-picked from commit (%s)\)'
    r')$'
    % ((r'[0-9a-f]{40}',) * 3))


def update(git_repo, remote_name):
    subprocess.check_call(['git', 'remote', 'update', remote_name],
                          cwd=git_repo)


def get_backports(git_repo, remote_name):
    branches = kernel_sec.branch.get_stable_branches(git_repo, remote_name)
    backports = {}

    for branch_name in branches:
        base_ver = kernel_sec.branch.get_stable_branch_base_ver(branch_name)
        log_proc = subprocess.Popen(
            # Format with hash on one line, body on following lines indented
            # by 1
            ['git', 'log', '--no-notes', '--pretty=%H%n%w(0,1,1)%b',
             'v%s..%s/%s' % (base_ver, remote_name, branch_name)],
            cwd=git_repo, stdout=subprocess.PIPE)

        for line in io.TextIOWrapper(log_proc.stdout, encoding='utf-8',
                                     errors='ignore'):
            if line[0] != ' ':
                stable_commit = line.rstrip('\n')
            else:
                match = BACKPORT_COMMIT_RE.match(line[1:])
                if match:
                    mainline_commit = match.group(1) or match.group(2) \
                                      or match.group(3)
                    backports.setdefault(mainline_commit, {})[branch_name] \
                        = stable_commit

    return backports


def add_backports(issue_commits, all_backports):
    try:
        mainline_commits = issue_commits['mainline']
    except KeyError:
        return False

    changed = False

    # Find backports of each commit to each stable branch
    branch_commits = {}
    for commit in mainline_commits:
        try:
            commit_backports = all_backports[commit]
        except KeyError:
            continue
        for branch_name in commit_backports:
            branch_commits.setdefault(branch_name, []).append(
                commit_backports[branch_name])

    # Only record if all commits have been backported and nothing recorded
    # for this branch yet
    for branch_name in branch_commits:
        if len(branch_commits[branch_name]) == len(mainline_commits):
            issue_branch_commits = issue_commits.setdefault(branch_name, [])
            if not issue_branch_commits:
                issue_branch_commits.extend(branch_commits[branch_name])
                changed = True

    return changed


def main(git_repo, remote_name):
    update(git_repo, remote_name)
    backports = get_backports(git_repo, remote_name)

    issues = set(kernel_sec.issue.get_list())
    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)
        changed = False
        for name in ['introduced-by', 'fixed-by']:
            try:
                commits = issue[name]
            except KeyError:
                continue
            else:
                changed |= add_backports(commits, backports)
        if changed:
            kernel_sec.issue.save(cve_id, issue)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=('Import information about backported fixes and '
                     'regressions from commit messages on stable branches.'))
    parser.add_argument('--git-repo',
                        dest='git_repo', default='../kernel',
                        help=('git repository from which to read commit logs '
                              '(default: ../kernel)'),
                        metavar='DIRECTORY')
    parser.add_argument('--stable-remote',
                        dest='stable_remote_name', default='stable',
                        help=('git remote for stable branches '
                              '(default: stable)'),
                        metavar='NAME')
    args = parser.parse_args()
    main(args.git_repo, args.stable_remote_name)
