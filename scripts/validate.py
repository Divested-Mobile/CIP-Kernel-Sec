#!/usr/bin/python3

# Copyright 2017 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import sys

from kernel_sec.issue import get_filename, get_list, load, load_filename, validate

def main(*names):
    import glob

    rc = 0
    if len(names) == 0:
        names = [get_filename(cve_id) for cve_id in get_list()]

    for name in names:
        try:
            validate(load_filename(name))
        except Exception as e:
            rc = 1
            print('%s: %s' % (name, e), file=sys.stderr)

    sys.exit(rc)

if __name__ == '__main__':
    main(*sys.argv[1:])
