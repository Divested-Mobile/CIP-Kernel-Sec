#!/usr/bin/python3

import sys
import yaml

from kernel_sec.issue import validate

def main(*names):
    import glob

    rc = 0
    if len(names) == 0:
        names = glob.glob('issues/CVE-*.yml')

    for name in names:
        try:
            with open(name) as f:
                validate(yaml.safe_load(f))
        except Exception as e:
            rc = 1
            print('%s: %s' % (name, e), file=sys.stderr)

    sys.exit(rc)

if __name__ == '__main__':
    main(*sys.argv[1:])
