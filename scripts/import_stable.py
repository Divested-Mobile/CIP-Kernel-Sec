#!/usr/bin/python3

# Copyright 2017-2018 Codethink Ltd.
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

import kernel_sec.branch
import kernel_sec.issue


COMMIT_HASH_RE = r'[0-9a-f]{40}'
BACKPORT_COMMIT_TOP_RE = re.compile(
    r'^(?:' r'commit (%s)(?: upstream\.?)?'
    r'|'    r'\[ [Uu]pstream commit (%s) \]'
    r'|'    r'\(cherry[- ]picked from commit (%s)\)'
    r')$'
    % (COMMIT_HASH_RE, COMMIT_HASH_RE, COMMIT_HASH_RE))
BACKPORT_COMMIT_BOTTOM_RE = re.compile(
    r'^\(cherry[- ]picked from commit (%s)\)$'
    % COMMIT_HASH_RE)


def update(git_repo, remote_name):
    subprocess.check_call(['git', 'remote', 'update', remote_name],
                          cwd=git_repo)


def get_backports(git_repo, remote_name, branches):
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
                commit_re = BACKPORT_COMMIT_TOP_RE  # next line is top of body
            else:
                match = commit_re.match(line[1:])
                if match:
                    mainline_commit = match.group(1) or match.group(2) \
                                      or match.group(3)
                    backports.setdefault(mainline_commit, {})[branch_name] \
                        = stable_commit
                if line.strip() != '':
                    commit_re = BACKPORT_COMMIT_BOTTOM_RE  # next line is not top

    return backports


def add_backports(branches, c_b_map, issue_commits, all_backports,
                  debug_context=None):
    try:
        mainline_commits = issue_commits['mainline']
    except KeyError:
        return False
    if mainline_commits == 'never':
        return False

    changed = False

    for branch_name in branches:
        # Don't replace a non-empty field
        if issue_commits.get(branch_name):
            if debug_context:
                print('%s/%s: already set' % (debug_context, branch_name))
            continue

        branch_commits = []
        for commit in mainline_commits:
            # Was this commit included before the branch point?
            if c_b_map.is_commit_in_branch(commit, branch_name):
                if debug_context:
                    print('%s/%s: includes %s' %
                          (debug_context, branch_name, commit))
                branch_commits.append(commit)
            else:
                # Has it been backported?
                try:
                    backport_commit = all_backports[commit][branch_name]
                except KeyError:
                    if debug_context:
                        print('%s/%s: missing %s' %
                              (debug_context, branch_name, commit))
                    continue
                if debug_context:
                    print('%s/%s: includes backport of %s' %
                          (debug_context, branch_name, commit))
                branch_commits.append(backport_commit)

        if len(branch_commits) == len(mainline_commits):
            # All required commits were found.  If some or all of them are
            # backports then record them.
            if branch_commits != mainline_commits:
                if debug_context:
                    print('%s/%s: recording commits' %
                          (debug_context, branch_name))
                issue_commits.setdefault(branch_name, []).extend(branch_commits)
                changed = True
            else:
                if debug_context:
                    print('%s/%s: not recording commits - same as mainline' %
                          (debug_context, branch_name))

    return changed


def main(git_repo, mainline_remote_name, stable_remote_name, debug=False):
    stable_branches = kernel_sec.branch.get_live_stable_branches(
        git_repo, stable_remote_name)
    branches = stable_branches + ['mainline']

    update(git_repo, stable_remote_name)
    backports = get_backports(git_repo, stable_remote_name, stable_branches)
    c_b_map = kernel_sec.branch.CommitBranchMap(git_repo, mainline_remote_name,
                                                branches)

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
                debug_context = '%s/%s' % (cve_id, name) if debug else None
                changed |= add_backports(stable_branches, c_b_map,
                                         commits, backports,
                                         debug_context=debug_context)
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
    parser.add_argument('--mainline-remote',
                        dest='mainline_remote_name', default='torvalds',
                        help='git remote for mainline (default: torvalds)',
                        metavar='NAME')
    parser.add_argument('--stable-remote',
                        dest='stable_remote_name', default='stable',
                        help=('git remote for stable branches '
                              '(default: stable)'),
                        metavar='NAME')
    parser.add_argument('--debug',
                        dest='debug', action='store_true',
                        help='enable debugging output')
    args = parser.parse_args()
    main(args.git_repo, args.mainline_remote_name, args.stable_remote_name,
         args.debug)
