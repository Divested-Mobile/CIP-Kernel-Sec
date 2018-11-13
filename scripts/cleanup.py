#!/usr/bin/python3

# Copyright 2018 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import kernel_sec.issue

def main():
    issues = set(kernel_sec.issue.get_list())
    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)
        kernel_sec.issue.save(cve_id, issue)

if __name__ == '__main__':
    main()
