#!/usr/bin/python3

# Copyright 2020 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import re

import kernel_sec.issue


def main():
    cip_branch_re = re.compile(r'^linux-([\d.]+)\.y-cip(-rt)?$')
    stable_branch_re = re.compile(r'^linux-([\d.]+)\.y$')

    issues = set(kernel_sec.issue.get_list())

    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)

        for name in ['introduced-by', 'fixed-by', 'ignore']:
            old_value = issue.get(name)
            if not old_value:
                continue

            issue[name] = value = {}
            for branch_name, branch_value in old_value.items():
                match = cip_branch_re.match(branch_name)
                if match:
                    branch_name = match.expand(r'cip/\1\2')
                else:
                    match = stable_branch_re.match(branch_name)
                    if match:
                        branch_name = match.expand(r'stable/\1')
                value[branch_name] = branch_value

        kernel_sec.issue.save(cve_id, issue)


if __name__ == '__main__':
    main()
