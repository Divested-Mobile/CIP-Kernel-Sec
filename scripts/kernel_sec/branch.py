# Copyright 2017 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import re
import subprocess

_STABLE_BRANCH_RE = re.compile(r'^linux-([\d.]+)\.y$')

def get_base_ver_stable_branch(base_ver):
    return 'linux-%s.y' % base_ver

def get_stable_branch_base_ver(branch_name):
    match = _STABLE_BRANCH_RE.match(branch_name)
    return match and match.group(1)

def get_stable_branches(git_repo, remote_name='stable'):
    branches = []

    branch_text = str(
        subprocess.check_output(
            ['git', 'branch', '--list', '-r', '--no-color', '--column=never',
             remote_name + '/*'],
            cwd=git_repo),
        encoding='utf-8', errors='strict')
    branch_prefix = remote_name + '/'

    for branch_name in branch_text.strip().split():
        assert branch_name.startswith(branch_prefix)
        branch_name = branch_name[len(branch_prefix):]

        if get_stable_branch_base_ver(branch_name):
            branches.append(branch_name)

    return branches

def get_live_stable_branches(*args, **kwargs):
    # TODO: Pull list of longterm branches from
    # https://www.kernel.org/category/releases.html ?
    # For now, err on the side of inclusion and only exclude known dead
    # branches.
    dead_branches = set((
        'linux-2.6.11.y', 'linux-2.6.12.y', 'linux-2.6.13.y', 'linux-2.6.14.y',
        'linux-2.6.15.y', 'linux-2.6.16.y', 'linux-2.6.17.y', 'linux-2.6.18.y',
        'linux-2.6.19.y', 'linux-2.6.20.y', 'linux-2.6.21.y', 'linux-2.6.22.y',
        'linux-2.6.23.y', 'linux-2.6.24.y', 'linux-2.6.25.y', 'linux-2.6.26.y',
        'linux-2.6.27.y', 'linux-2.6.28.y', 'linux-2.6.29.y', 'linux-2.6.30.y',
        'linux-2.6.31.y', 'linux-2.6.32.y', 'linux-2.6.33.y', 'linux-2.6.34.y',
        'linux-2.6.35.y', 'linux-2.6.36.y', 'linux-2.6.37.y', 'linux-2.6.38.y',
        'linux-2.6.39.y', 'linux-3.0.y', 'linux-3.1.y', 'linux-3.3.y',
        'linux-3.4.y', 'linux-3.5.y', 'linux-3.6.y', 'linux-3.7.y',
        'linux-3.8.y', 'linux-3.9.y', 'linux-3.10.y', 'linux-3.11.y',
        'linux-3.12.y', 'linux-3.13.y', 'linux-3.14.y', 'linux-3.15.y',
        'linux-3.17.y', 'linux-3.19.y', 'linux-4.0.y', 'linux-4.2.y',
        'linux-4.3.y', 'linux-4.5.y', 'linux-4.6.y', 'linux-4.7.y',
        'linux-4.8.y', 'linux-4.10.y', 'linux-4.11.y', 'linux-4.12.y',
        'linux-4.13.y'))

    return [branch_name for branch_name in get_stable_branches(*args, **kwargs)
            if branch_name not in dead_branches]
