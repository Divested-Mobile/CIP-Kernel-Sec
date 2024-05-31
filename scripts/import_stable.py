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


RE_USE = {'hash': r'[0-9a-f]{40}'}
BACKPORT_COMMIT_TOP_RE = re.compile(
    r'^(?:' r'commit ({hash})(?: upstream\.?)?'
    r'|'    r'\[ [Uu]pstream commit ({hash}) \]'
    r'|'    r'\[ commit ({hash}) upstream \]'
    r')$'
    .format(**RE_USE))
BACKPORT_COMMIT_ANYWHERE_RE = re.compile(
    r'^(?:' r'\(cherry[- ]picked from commit ({hash})\)'
    r'|'    r'\(backported from(?: commit)? ({hash})\b.*'  # Ubuntu
    r')$'
    .format(**RE_USE))


def get_backports(git_repo, branches, debug=False):
    backports = {}

    for branch in branches:
        # Skip mainline and any branches that we can't access
        if 'base_ver' not in branch \
           or 'git_remote' not in branch \
           or 'git_name' not in branch:
            continue

        branch_name = branch['short_name']
        base_ver = branch['base_ver']
        log_proc = subprocess.Popen(
            # Format with hash on one line, body on following lines indented
            # by 1
            ['git', 'log', '--no-notes', '--pretty=%H%n%w(0,1,1)%b',
             'v%s..%s/%s'
             % (base_ver, branch['git_remote']['git_name'],
                branch['git_name'])],
            cwd=git_repo, stdout=subprocess.PIPE)

        for line in io.TextIOWrapper(log_proc.stdout, encoding='utf-8',
                                     errors='ignore'):
            if line[0] != ' ':
                stable_commit = line.rstrip('\n')
                body_line_no = 1
            else:
                match = ((BACKPORT_COMMIT_TOP_RE.match(line[1:])
                          if body_line_no <= 3 else None)
                         or BACKPORT_COMMIT_ANYWHERE_RE.match(line[1:]))
                if match:
                    mainline_commit = ''.join(match.groups(''))
                    if debug:
                        print('%s: %s is backport of %s'
                              % (branch_name, stable_commit, mainline_commit))
                    backports.setdefault(mainline_commit, {})[branch_name] \
                        = stable_commit
                if line.strip() != '':
                    body_line_no += 1

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

    for branch in branches:
        branch_name = branch['short_name']
        if branch_name == 'mainline':
            continue

        # Don't replace a non-empty field
        if issue_commits.get(branch_name):
            if debug_context:
                print('%s/%s: already set' % (debug_context, branch_name))
            continue

        branch_commits = []
        for commit in mainline_commits:
            # Was this commit included before the branch point?
            if c_b_map.is_commit_in_branch(commit, branch):
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
                issue_commits.setdefault(
                    branch_name, []).extend(branch_commits)
                changed = True
            else:
                if debug_context:
                    print('%s/%s: not recording commits - same as mainline' %
                          (debug_context, branch_name))

    return changed


def main(git_repo, remotes, no_remote_update, debug=False):
    branches = kernel_sec.branch.get_live_branches(remotes)
    remote_names = set(branch['git_remote']['git_name']
                       for branch in branches
                       if 'git_remote' in branch)

    if not no_remote_update:
        for remote_name in remote_names:
            kernel_sec.branch.remote_update(git_repo, remote_name)
    backports = get_backports(git_repo, branches, debug)
    c_b_map = kernel_sec.branch.CommitBranchMap(git_repo, branches)

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
                changed |= add_backports(branches, c_b_map,
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
    parser.add_argument('--remote-name',
                        dest='remote_name', action='append', default=[],
                        help='git remote name mappings, e.g. stable:mystable',
                        metavar='NAME:OTHER-NAME')
    parser.add_argument('--mainline-remote',
                        dest='mainline_remote_name',
                        help="git remote name to use instead of 'torvalds'",
                        metavar='OTHER-NAME')
    parser.add_argument('--stable-remote',
                        dest='stable_remote_name',
                        help="git remote name to use instead of 'stable'",
                        metavar='OTHER-NAME')
    parser.add_argument('--debug',
                        dest='debug', action='store_true',
                        help='enable debugging output')
    parser.add_argument('--no-remote-update',
                        action='store_true',
                        help='skip remote repository update')

    args = parser.parse_args()
    remotes = kernel_sec.branch.get_remotes(args.remote_name,
                                            mainline=args.mainline_remote_name,
                                            stable=args.stable_remote_name)
    kernel_sec.branch.check_git_repo(args.git_repo, remotes)
    main(args.git_repo, remotes, args.no_remote_update, args.debug)
