#!/usr/bin/python3

# Copyright 2020 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import kernel_sec.issue


def main():
    issues = set(kernel_sec.issue.get_list())

    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)
        old_comments = issue.get('comments')
        if not old_comments:
            continue

        issue['comments'] = comments = {}
        for name, value in old_comments.items():
            if name == 'Debian':
                name = 'debian'
            elif name.startswith('Debian-'):
                name = 'debian/' + name[7:]
            elif name == 'Ubuntu':
                name = 'ubuntu'
            elif name.startswith('Ubuntu-'):
                name = 'ubuntu/' + name[7:]
            comments[name] = value
        kernel_sec.issue.save(cve_id, issue)


if __name__ == '__main__':
    main()
