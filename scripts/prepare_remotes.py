#!/usr/bin/python3

# Copyright 2019 Toshiba corp.
# Based on import_stable.py by Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

# Helper script that prepares the local git repository with the configured
# remote branches

import argparse
import os
import subprocess

import kernel_sec.branch


def main(git_repo, remotes):
    if os.path.isdir(git_repo):
        existing_remotes = set(kernel_sec.branch.remote_list(git_repo))
    else:
        os.mkdir(git_repo)
        subprocess.check_call(['git', 'init', '.'], cwd=git_repo)
        existing_remotes = set()

    for key in remotes.keys():
        remote = remotes[key]  # __getitem__ will add git_name
        remote_name = remote['git_name']
        if remote_name in existing_remotes:
            fetch_nego_algo = 'default'
        else:
            kernel_sec.branch.remote_add(
                git_repo, remote_name, remote['git_repo_url'])
            # Some remotes will be *extremely* slow to fetch
            # initially without this
            fetch_nego_algo = 'skipping'
        kernel_sec.branch.remote_update(git_repo, remote_name,
                                        fetch_nego_algo=fetch_nego_algo)

    # self-check
    kernel_sec.branch.check_git_repo(git_repo, remotes)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=('Prepare local git repository with configured remotes.'))
    parser.add_argument('--git-repo',
                        dest='git_repo', default='../kernel',
                        help=('local git repository location '
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
    args = parser.parse_args()
    remotes = kernel_sec.branch.get_remotes(args.remote_name,
                                            mainline=args.mainline_remote_name,
                                            stable=args.stable_remote_name)
    main(args.git_repo, remotes)
