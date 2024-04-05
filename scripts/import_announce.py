#!/usr/bin/python3

# Copyright 2024 Cybertrust Japan Co., Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import os
import subprocess
import glob
import json
import sys
import re
import argparse

import time
import requests
from html.parser import HTMLParser

import kernel_sec.branch
import kernel_sec.issue

import pprint

IMPORT_DIR = 'import/linux-kernel-vulns'

FIXES_TAG_PATTERN = r'Fixes: (.*)'

# For get announce mail url in lore.kernel.org
LORE_BASE_URL = "https://lore.kernel.org/linux-cve-announce"
LORE_SEARCH_QUERY = "?q="
LINK_PATTERN = r"^\d+\S+@\S+"

class LoreHtmlParser(HTMLParser):
    def __init__(self):
        super().__init__()

        self.start = True
        self.link = None

    def handle_starttag(self, tag, attrs):
        if not tag == "a":
            return

        self.start = True
        if len(attrs) > 0:
            href, data = attrs[0]
            if re.match(LINK_PATTERN, data):
                if self.link is None:
                    self.link = f"{LORE_BASE_URL}/{data}"

    def handle_endtag(self, tag):
        if tag == "a":
            self.start = False

def get_proxies():
    https_proxy = None

    if 'https_proxy' in os.environ:
        https_proxy = os.environ['https_proxy']
    elif 'HTTPS_PROXY' in os.environ:
        https_proxy = os.environ['HTTPS_PROXY']
    else:
        return None

    return {
        'https': https_proxy,
    }

def get_lore_cve_announce_url(cve):
    url = f"{LORE_BASE_URL}/{LORE_SEARCH_QUERY}{cve}"

    proxies = get_proxies()
    res = requests.get(url, proxies=proxies)

    try:
        res = requests.get(url, proxies=proxies, timeout=5)
    except:
        print(f"Failed to get announce mail url for {cve}")
        return None

    if not res.status_code == 200:
        print(f"Failed to get page. http response {res.status_code}")
        return None

    html = res.text
        
    parser = LoreHtmlParser()
    parser.feed(html)
    time.sleep(1) # Wait sometime to not continuously access to lore.kernel.org
    return parser.link

def find_first_introduced_version(git_repo, commit_hash):
    res = subprocess.run(['git', 'tag', '--sort=taggerdate', '--contains', commit_hash, '-l', 'v*'],
                 capture_output=True, text=True,
                 cwd=git_repo)

    if res.returncode:
        #print(f"Couldn't find any tag contains {commit_hash}")
        return None

    tags = []
    tmp = res.stdout.split('\n')
    for tag in tmp:
        if not ('-st' in tag or
            '-cip' in tag or
            '-rt' in tag):
            tags.append(tag)

    return tags[0]

def run_git_rev_parse(git_repo, short_hash):
    res = subprocess.run(['git', 'rev-parse', short_hash],
                 capture_output=True, text=True,
                 cwd=git_repo)
 
    if res.returncode:
        #print(f"Couldn't parse hash {short_hash}")
        return None

    return res.stdout.strip()

def get_commit_subject(git_repo, commit_hash):
    res = subprocess.run(['git', 'log', '-n', '1',
                '--pretty="%s"',
                commit_hash],
                capture_output=True, text=True,
                cwd=git_repo)
 
    if res.returncode:
        #print(f"Couldn't get commit subject from {commit_hash}")
        return ''

    return res.stdout.strip()

def get_fixes(git_repo, commit_hash):
    res = subprocess.run(['git', 'log', '-n', '1',
                commit_hash],
                capture_output=True, text=True,
                cwd=git_repo)
 
    if res.returncode:
        return None

    match = re.findall(FIXES_TAG_PATTERN, res.stdout)

    fixes = []
    if match:
        for line in match:
            tmp = line.split(' ')
            fixes_hash = run_git_rev_parse(git_repo, tmp[0].strip())
            if fixes_hash:
                fixes.append({
                    'fixes_hash': fixes_hash,
                    'subject': ' '.join(tmp[1:]).strip(),
                })
        return fixes

    return None

def load_cve_announce(f, branches, git_repo):
    data = json.load(f)

    description = data['containers']['cna']['title']
    cve_id = data['cveMetadata']['cveID']

    versions = {}

    # Get Introduced/Fixed commit information
    affected = data['containers']['cna']['affected']

    if len(affected) > 2:
        print(f"{cve_id} has more than two entries in affected")

    vuln_info = {}

    for i in range(len(affected)):
        vuln_info[i] = []

        for j in range(len(affected[i]['versions'])):
            versions = affected[i]['versions'][j]
            if not 'versionType' in versions or versions['version'] == '0':
                continue

            d = {
                'version': versions['version'],
                'versionType': versions['versionType'],
            }

            if 'lessThan' in versions:
                d['fixedVersion'] = versions['lessThan']
            elif 'lessThanOrEqual' in versions:
                d['fixedVersion'] = versions['lessThanOrEqual']
            else:
                print(f"{cve_id} is not contains lessThan/lessThanOrEqual attribute")

            vuln_info[i].append(d)

    #if not len(vuln_info[0]) == len(vuln_info[1]) or not len(vuln_info) == 2:
    #    print(f"\r{cve_id} only affects to LTS kernel", end='')
    #    pprint.pprint(vuln_info)
    #    return None

    track_target_versions = []
    for branch in branches: 
        track_target_versions.append(branch.split('/')[-1])
 
    issue = {
        'description': description,
        'references': [
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
        ],
        'fixed-by': {},
    }

    for url in data['containers']['cna']['references']:
        issue['references'].append(url['url'])

    fixedin_mainline = False

    for i in range(len(vuln_info[0])):
        if i >= len(vuln_info[1]):
            break

        # Get major and minor version string
        version = '.'.join(vuln_info[1][i]['version'].split('.')[:2])

        # Is this fixed in mainline?
        if vuln_info[1][i]['versionType'] == 'original_commit_for_fix':
            version = 'mainline'
            fixedin_mainline = True

        if version in track_target_versions:
            if not version == 'mainline':
                version = f"stable/{version}"

            issue['fixed-by'].update({ 
                version: [ run_git_rev_parse(git_repo, vuln_info[0][i]['fixedVersion']) ]
            })

            # Get introduced commits from mainline.
            # Other branchs can get it via import_stable.py
            if version == 'mainline':
                comment = ''
                fixed_version = run_git_rev_parse(git_repo, vuln_info[0][i]['fixedVersion'])
                fixes = get_fixes(git_repo, fixed_version)
        
                fixed_commits = []

                # Fixes is tag is not found in commit log but CVE informaion has fixes commit.
                # e.g. CVE-2021-46926
                if fixes:
                    for fix in fixes:
                        fixed_commits.append(fix['fixes_hash'])
                        tag = find_first_introduced_version(git_repo, fix['fixes_hash'])
                        if tag:
                            comment += f"Introduced by commit {fix['fixes_hash'][0:7]} {fix['subject']} in {tag}.\n"
 
                    issue['introduced-by'] = {
                        version: fixed_commits,
                    }
                else:
                    comment += 'Introduced commit is not determined.'

                fixed_in_tag = find_first_introduced_version(git_repo, issue['fixed-by']['mainline'][0])
                comment += f"Fixed in {fixed_in_tag}."

                issue['comments'] = {
                    'cip/cip-kernel-sec': comment
                }

        if not fixedin_mainline:
            issue['comments'] = {
                'cip/cip-kernel-sec': 'This CVE announce does not contain fixed commit in the mainline.',
            }

    return issue

def main(git_repo):
    branches = {
        branch['short_name']: branch
        for branch in kernel_sec.branch.get_live_branches(
            kernel_sec.branch.get_remotes([]))
    }

    # Create/update Git repository
    os.makedirs(IMPORT_DIR, 0o777, exist_ok=True)
    if os.path.isdir(IMPORT_DIR + '/.git'):
        subprocess.check_call(['git', 'pull'], cwd=IMPORT_DIR)
    else:
        subprocess.check_call(
            ['git', 'clone',
             'https://git.kernel.org/pub/scm/linux/security/vulns.git', '.'],
            cwd=IMPORT_DIR)

    our_issues = set(kernel_sec.issue.get_list())
    cve_announces = dict((os.path.basename(name.replace('.json', '')), name) for name in
                        glob.glob(IMPORT_DIR + '/cve/published/**/CVE-*.json'))
    
    for cve_id in cve_announces:
        # Test pattern
        # CVE-2021-47073: an introduced commit is determined.
        # CVE-2021-47069: contains 3 fixes tag.
        # CVE-2023-52476: an introduced commit is not determined.
        # CVE-2021-46985: an introduced commit is backported to older kernels.
        # CVE-2021-46922: backport issue. only stable/5.10 is vulnerable.
        # CVE-2021-46926: no fixes tag in commit log.
        # CVE-2023-52525: doesn't have mainline's fixed commit
        #if not cve_id == "CVE-2024-26781":
        #    continue
        print(f"\rChecking {cve_id}", end='')
        announce = cve_announces[cve_id]
        with open(announce) as f:
            theirs = load_cve_announce(f, branches, git_repo)
            if theirs is None:
                continue

            if cve_id not in our_issues:
                # New CVE
                announce_url = get_lore_cve_announce_url(cve_id)
                if announce_url is not None:
                    theirs['references'].append(announce_url)

                ours = theirs
            else:
                # Remove comment by cip/cip-kernel-sec from theirs to not modify old data
                theirs.pop('comments', None)
                ours = kernel_sec.issue.load(cve_id)
                kernel_sec.issue.validate(ours)
                if not kernel_sec.issue.merge_into(ours, theirs):
                    continue
            
            try:
                kernel_sec.issue.validate(ours)
            except ValueError as e:
                print('%s: %s' % (announce, e), file=sys.stderr)
                continue
            print(f"\nSave file issues/{cve_id}.yml")
            kernel_sec.issue.save(cve_id, ours)

    print("")
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description=('Import CVE information from https://git.kernel.org/pub/scm/linux/security/vulns.git'))
    parser.add_argument('--git-repo',
                        dest='git_repo', default='../kernel',
                        help=('git repository from which to get commit infomation '
                            '(default: ../kernel)'),
                        metavar='DIRECTORY')
    args = parser.parse_args()

    main(args.git_repo)
