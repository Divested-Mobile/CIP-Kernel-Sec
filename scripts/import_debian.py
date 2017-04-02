#!/usr/bin/python3

# Import information from Debian's kernel-sec repository.  The format is
# not documented but is based on Debian's variant of RFC822. See
# active/00boilerplate and scripts/filter-active.py in that repository.

from debian import deb822
import glob
import os.path
import re
import subprocess
import sys
import validate
import yaml

IMPORT_DIR = 'import/debian'

LINE_BREAK_RE = re.compile(r'\n\s*')
COMMA_SEP_RE = re.compile(r',\s*')
COMMENT_RE = re.compile(r'^(\w+)>\s+(.*)$')
STATUS_RE = re.compile(r'^\s*(?P<state>\S*)'
                       r'\s*(\((\S*,\s*)*\S*\s*\))?'
                       r'\s*(\[(?P<changerefs>(\S*,\s*)*\S*)\s*\])?')

def load_debian_issue(f):
    deb_issue = deb822.Deb822(f)
    issue = {}

    issue['summary'] = deb_issue['Description']

    references = [
        ref for ref in
        (LINE_BREAK_RE.split(deb_issue['References'].strip()) +
         LINE_BREAK_RE.split(deb_issue['Bugs'].strip()))
        if ref]
    if references:
        issue['references'] = references

    # Group and join comment lines by name
    comments = {}
    for line in LINE_BREAK_RE.split(deb_issue['Notes'].strip()):
        if not line:
            continue
        match = COMMENT_RE.match(line)
        if match:
            name = 'Debian-' + match.group(1)
            rest = match.group(2)
        else:
            name = 'Debian'
            rest = line
        comments.setdefault(name, []).append(rest)
    if comments:
        issue['comments'] = dict((name, '\n'.join(lines))
                                 for (name, lines) in comments.items())

    # Branch status
    for key in deb_issue:
        if key == 'upstream':
            branch = 'mainline'
        elif key.endswith('-upstream-stable'):
            branch = 'linux-%s.y' % key.replace('-upstream-stable', '')
        else:
            continue
        match = STATUS_RE.match(deb_issue[key])
        if match and \
           match.group('state') in ['pending', 'released'] and \
           match.group('changerefs'):
            # These are *usually* git commit hashes but could be patch names
            hashes = [ref
                      for ref in COMMA_SEP_RE.split(match.group('changerefs'))
                      if validate.is_git_hash(ref)]
            if hashes:
                issue.setdefault('fixed-by', {})[branch] = hashes

    return issue

def merge_into(ours, theirs):
    changed = False

    # Don't attempt to merge description.  As it is a mandatory field
    # we must already have a description.

    if 'references' in theirs:
        our_refs = ours.setdefault('references', [])
        for ref in theirs['references']:
            if ref not in our_refs:
                our_refs.append(ref)
                changed = True

    if 'comments' in theirs:
        our_comments = ours.setdefault('comments', {})
        for name, comment in theirs['comments'].items():
            # All imported comments have names starting 'Debian' so it
            # should be safe to overwrite existing comments with the
            # same name.
            assert name.startswith('Debian')
            if our_comments.get(name) != comment:
                our_comments[name] = comment
                changed = True

    if 'fixed-by' in theirs:
        our_fixed_by = ours.setdefault('fixed-by', {})
        for branch, hashes in theirs['fixed-by'].items():
            our_hashes = our_fixed_by.setdefault(branch, [])
            for h in hashes:
                if h not in our_hashes:
                    our_hashes.append(h)
                    changed = True

    return changed

def main():
    os.makedirs(IMPORT_DIR, 0o777, exist_ok=True)
    if os.path.isdir(IMPORT_DIR + '/.svn'):
        subprocess.check_call(['svn', 'update'], cwd=IMPORT_DIR)
    else:
        # XXX This is not secure; does Alioth support HTTP-S access to
        # Subversion repos?
        subprocess.check_call(['svn', 'checkout',
                               'svn://scm.alioth.debian.org/svn/kernel-sec/',
                               '.'],
                              cwd=IMPORT_DIR)

    our_issues = dict((os.path.basename(name)[:-4], name) for name in
                       glob.glob('issues/CVE-*.yml'))
    their_issues = dict((os.path.basename(name), name) for name in
                        glob.glob(IMPORT_DIR + '/active/CVE-*'))

    # Also look at retired issues that we already track, but not the
    # huge number of historical ones
    for cve_id in our_issues:
        if cve_id not in their_issues:
            retired_name = IMPORT_DIR + '/retired/' + cve_id
            if os.path.exists(retired_name):
                their_issues[cve_id] = retired_name

    for cve_id in their_issues:
        their_filename = their_issues[cve_id]
        with open(their_filename) as f:
            try:
                theirs = load_debian_issue(f)
            except (KeyError, ValueError, UnicodeDecodeError):
                print('Failed to parse %s' % their_filename, file=sys.stderr)
                continue

        try:
            our_filename = our_issues[cve_id]
        except KeyError:
            # Copy theirs
            ours = theirs
            our_filename = 'issues/%s.yml' % cve_id
        else:
            # Merge into ours
            with open(our_filename) as f:
                ours = yaml.safe_load(f)
            validate.validate(ours) # check that it's good to start with
            if not merge_into(ours, theirs):
                continue

        try:
            validate.validate(ours)
        except ValueError as e:
            print('%s: %s' % (their_filename, e), file=sys.stderr)
            continue

        with open(our_filename, 'w') as f:
            yaml.safe_dump(ours, f)

if __name__ == '__main__':
    main()
