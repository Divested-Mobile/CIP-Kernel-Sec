#!/usr/bin/python3

# Copyright 2024 Cybertrust Japan Co., Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import glob
import os
import yaml
import json
import kernel_sec.issue
import pprint

IMPORT_DIR = "import/linux-kernel-vulns"

REJECTED_TITLE_PREFIX = "[REJECTED]"
REJECTED_COMMENT = "This CVE was rejected."

def update_ignore_data(data):
    data["description"] = f"{REJECTED_TITLE_PREFIX}: {data['description']}"
    if not "ignore" in data:
        data["ignore"] = {}

    data["ignore"]["all"] = REJECTED_COMMENT

    if not "comments" in data:
        data["comments"] = {}

    if not "cip/cip-kernel-sec" in data["comments"]:
        data["comments"]["cip/cip-kernel-sec"] = REJECTED_COMMENT
    else:
        old = data["comments"]["cip/cip-kernel-sec"]
        data["comments"]["cip/cip-kernel-sec"] = f"{REJECTED_COMMENT} {old}"

    return data

def create_new_cve_data(rejected_cve):
    with open(rejected_cve) as f:
        data = json.load(f)

        description = data['containers']['cna']['title']

        cve_data = {
            "description": description,
        }

        return update_ignore_data(cve_data)

def update_cve_data(cve_file):
    with open(cve_file) as f:
        data = yaml.safe_load(f.read())
        if data["description"].startswith(REJECTED_TITLE_PREFIX):
            return None

        return update_ignore_data(data)

def find_rejected_cves():
    return dict((os.path.basename(name.replace('.json', '')), name) for name in
                        glob.glob(IMPORT_DIR + '/cve/rejected/**/CVE-*.json'))


def get_all_cves_in_vulns():
    return dict((os.path.basename(name.replace('.json', '')), name) for name in
                        glob.glob(IMPORT_DIR + '/cve/**/**/CVE-*.json'))

def get_rejected_cves_in_cip_kernel_sec():
    rejected_files = []

    files = glob.glob('issues/*.yml')
    for f  in files:
        with open(f) as fd:
            yml = yaml.safe_load(fd.read())
        if REJECTED_TITLE_PREFIX in yml['description']:
            rejected_files.append(f)

    return dict((os.path.basename(name.replace('.yml', '')), name) for name in rejected_files)

def rejected_to_published(rejected_in_linux):
    rejected_in_cip = get_rejected_cves_in_cip_kernel_sec()
    all_cves_in_vulns = get_all_cves_in_vulns()

    for cve in rejected_in_cip:
        if cve in rejected_in_linux:
            #print(f"{cve} is already rejected")
            continue
        
        if not cve in all_cves_in_vulns:
            #print(f"{cve} is not managed in vulns")
            continue

        with open(rejected_in_cip[cve]) as f:
            yml = yaml.safe_load(f.read())
            yml['description'] = yml['description'].replace(f"{REJECTED_TITLE_PREFIX}: ", '')
            if 'all' in yml['ignore']:
                if yml['ignore']['all'] == REJECTED_COMMENT:
                    del yml['ignore']['all']
            try:
                kernel_sec.issue.validate(yml)
            except ValueError as e:
                print('%s: %s' % (announce, e), file=sys.stderr)
                continue
            kernel_sec.issue.save(cve, yml)
            print(f"Reverted: issues/{cve}.yml")

def published_to_rejected(rejected_in_linux):
    for cve_id in rejected_in_linux:
        cve_file = f"issues/{cve_id}.yml"
        if os.path.exists(cve_file):
            cve_data = update_cve_data(cve_file)
        else:
            cve_data = create_new_cve_data(rejected_in_linux[cve_id])

        if cve_data:
            try:
                kernel_sec.issue.validate(cve_data)
            except ValueError as e:
                print('%s: %s' % (announce, e), file=sys.stderr)
                continue
            kernel_sec.issue.save(cve_id, cve_data)
            print(f"Rejected: issues/{cve_id}.yml")

def main():
    rejected_in_linux = find_rejected_cves()
    published_to_rejected(rejected_in_linux)
    rejected_to_published(rejected_in_linux)

if __name__ == "__main__":
    main()
