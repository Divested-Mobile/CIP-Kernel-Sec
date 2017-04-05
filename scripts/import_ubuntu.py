#!/usr/bin/python3

# Import information from ubuntu-cve-tracker repository.  The format is
# roughly documented in the README file.  See also the load_cve()
# function in scripts/cve_lib.py.

import glob
import os
import os.path
import re
import subprocess
import sys

import kernel_sec.issue

IMPORT_DIR = 'import/ubuntu'

BREAK_FIX_RE = re.compile(r'^break-fix: (?:([0-9a-f]{40})|[-\w]+)'
                          r' (?:([0-9a-f]{40})|[-\w]+)$')

# Based on load_cve() in scripts/cve_lib.py
def load_cve(cve, strict=False):
    '''Loads a given CVE into:
       dict( fields...
             'pkgs' -> dict(  pkg -> dict(  release ->  (state, notes)   ) )
           )
    '''

    EXIT_FAIL = 1
    EXIT_OKAY = 0

    msg = ''
    code = EXIT_OKAY

    data = dict()
    data.setdefault('tags',dict())
    affected = dict()
    lastfield = None
    fields_seen = []

    for line in cve:
        line = line.rstrip()

        # Ignore blank/commented lines
        if len(line) == 0 or line.startswith('#'):
            continue
        if line.startswith(' '):
            try:
                data[lastfield] += '\n%s' % (line[1:])
            except KeyError as e:
                msg += "%s: bad line '%s' (%s)\n" % (cve, line, e)
                code = EXIT_FAIL
            continue

        try:
            field, value = line.split(':',1)
        except ValueError as e:
            msg += "%s: bad line '%s' (%s)\n" % (cve, line, e)
            code = EXIT_FAIL
            continue

        lastfield = field = field.strip()
        if field in fields_seen:
            msg += "%s: repeated field '%s'\n" % (cve, field)
            code = EXIT_FAIL
        else:
            fields_seen.append(field)
        value = value.strip()
        if field == 'Candidate':
            data.setdefault(field,value)
            if value != "" and not value.startswith('CVE-') and not value.startswith('UEM-') and not value.startswith('EMB-'):
                msg += "%s: unknown Candidate '%s' (must be /(CVE|UEM|EMB)-/)\n" % (cve, value)
                code = EXIT_FAIL
        elif 'Priority' in field:
            # For now, throw away comments on Priority fields
            if ' ' in value:
                value = value.split()[0]
            if 'Priority_' in field:
                try:
                    foo, pkg = field.split('_',1)
                except ValueError:
                    msg += "%s: bad field with 'Priority_': '%s'\n" % (cve, field)
                    code = EXIT_FAIL
                    continue
            data.setdefault(field,value)
        elif 'Patches_' in field:
            '''These are raw fields'''
            try:
                foo, pkg = field.split('_',1)
            except ValueError:
                msg += "%s: bad field with 'Patches_': '%s'\n" % (cve, field)
                code = EXIT_FAIL
                continue
            data.setdefault(field,value)
        elif 'Tags_' in field:
            '''These are processed into the "tags" hash'''
            try:
                foo, pkg = field.split('_',1)
            except ValueError:
                msg += "%s: bad field with 'Tags_': '%s'\n" % (cve, field)
                code = EXIT_FAIL
                continue
            data['tags'].setdefault(pkg, set())
            for word in value.strip().split(' '):
                data['tags'][pkg].add(word)
        elif '_' in field:
            try:
                release, pkg = field.split('_',1)
            except ValueError:
                msg += "%s: bad field with '_': '%s'\n" % (cve, field)
                code = EXIT_FAIL
                continue
            try:
                info = value.split(' ',1)
            except ValueError:
                msg += "%s: missing state for '%s': '%s'\n" % (cve, field, value)
                code = EXIT_FAIL
                continue
            state = info[0]
            if state == '':
                state = 'needs-triage'

            if len(info) < 2:
                notes = ""
            else:
                notes = info[1].strip()
            if notes.startswith('('):
                notes = notes[1:]
            if notes.endswith(')'):
                notes = notes[:-1]

            # Work-around for old-style of only recording released versions
            if notes == '' and state[0] in ('0123456789'):
                notes = state
                state = 'released'

            if state not in ['needs-triage','needed','active','pending','released','deferred','DNE','ignored','not-affected']:
                msg += "%s: %s_%s has unknown state: '%s'\n" % (cve, release, pkg, state)
                code = EXIT_FAIL

            # Verify "released" kernels have version notes
            #if state == 'released' and pkg in kernel_srcs and notes == '':
            #    msg += "%s: %s_%s has state '%s' but lacks version note\n" % (cve, release, pkg, state)
            #    code = EXIT_FAIL

            # Verify "active" states have an Assignee
            if state == 'active' and data['Assigned-to'].strip() == "":
                msg += "%s: %s_%s has state '%s' but lacks 'Assigned-to'\n" % (cve, release, pkg, state)
                code = EXIT_FAIL

            affected.setdefault(pkg,dict())
            affected[pkg].setdefault(release,[state,notes])
        elif field not in ['References', 'Description', 'Ubuntu-Description', 'Notes', 'Bugs', 'Assigned-to', 'Approved-by', 'PublicDate', 'PublicDateAtUSN', 'CRD', 'Discovered-by']:
            msg += "%s: unknown field '%s'\n" % (cve, field)
            code = EXIT_FAIL
        else:
            data.setdefault(field,value)

    # Check for required fields
    for field in ['Candidate','PublicDate','Description']:
        if field not in data:
            msg += "%s: missing field '%s'\n" % (cve, field)
            code = EXIT_FAIL
        nonempty = ['Candidate']
        if strict:
            nonempty += ['PublicDate']
        if field in nonempty and data[field].strip() == "":
            msg += "%s: required field '%s' is empty\n" % (cve, field)
            code = EXIT_FAIL

    # Fill in defaults for missing fields
    if 'Priority' not in data:
        data.setdefault('Priority','untriaged')
    # Perform override fields
    if 'PublicDateAtUSN' in data:
        data['PublicDate'] = data['PublicDateAtUSN']
    if 'CRD' in data and data['PublicDate'] != data['CRD']:
        data['PublicDate'] = data['CRD']

    data['pkgs'] = affected

    if code != EXIT_OKAY:
        raise ValueError(msg.strip())
    return data

class NonKernelIssue(Exception):
    pass

def load_ubuntu_issue(f):
    ubu_issue = load_cve(f)
    issue = {}

    assert ubu_issue['Candidate'] == os.path.basename(f.name)

    if 'linux' not in ubu_issue['pkgs']:
        raise NonKernelIssue()

    issue['description'] = ubu_issue['Description'].strip()

    refs = ubu_issue.get('References', '').strip().split() + \
           ubu_issue.get('Bugs', '').strip().split()
    if refs:
        issue['references'] = refs

    # TODO: comments

    disc = ubu_issue.get('Discovered-by', '').strip()
    if disc:
        issue['reporters'] = [disc]

    patches = ubu_issue.get('Patches_linux', '').strip()
    match = BREAK_FIX_RE.match(patches)
    if match and match.group(1):
        issue.setdefault('introduced-by', {})['master'] = [match.group(1)]
    if match and match.group(2):
        issue.setdefault('fixed-by', {})['master'] = [match.group(2)]

    return issue

def merge_into(ours, theirs):
    return False

def main():
    os.makedirs(IMPORT_DIR, 0o777, exist_ok=True)
    if os.path.isdir(IMPORT_DIR + '/.bzr'):
        subprocess.check_call(['bzr', 'update'], cwd=IMPORT_DIR)
    else:
        subprocess.check_call(['bzr', 'checkout', 'lp:ubuntu-cve-tracker', '.'],
                              cwd=IMPORT_DIR)

    our_issues = set(kernel_sec.issue.get_list())
    their_issues = dict((os.path.basename(name), name) for name in
                        glob.glob(IMPORT_DIR + '/active/CVE-*'))

    # Also look at ignored and retired issues that we already track,
    # but not the huge number of historical ones
    for cve_id in our_issues:
        if cve_id not in their_issues:
            for state in ['ignored', 'retired']:
                their_filename = IMPORT_DIR + '/' + state + '/' + cve_id
                if os.path.exists(their_filename):
                    their_issues[cve_id] = their_filename

    for cve_id in their_issues:
        their_filename = their_issues[cve_id]
        with open(their_filename, encoding='utf-8') as f:
            try:
                theirs = load_ubuntu_issue(f)
            except NonKernelIssue:
                continue
            except (KeyError, ValueError, UnicodeDecodeError):
                print('Failed to parse %s' % their_filename, file=sys.stderr)
                continue

        if cve_id not in our_issues:
            # Copy theirs
            ours = theirs
        else:
            # Merge into ours
            ours = kernel_sec.issue.load(cve_id)
            kernel_sec.issue.validate(ours) # check that it's good to start with
            if not merge_into(ours, theirs):
                continue

        try:
            kernel_sec.issue.validate(ours)
        except ValueError as e:
            print('%s: %s' % (their_filename, e), file=sys.stderr)
            continue

        kernel_sec.issue.save(cve_id, ours)

if __name__ == '__main__':
    main()
