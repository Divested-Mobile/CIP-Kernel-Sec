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

def main():
    rejected_cves = find_rejected_cves()

    for cve_id in rejected_cves:
        cve_file = f"issues/{cve_id}.yml"
        if os.path.exists(cve_file):
            cve_data = update_cve_data(cve_file)
        else:
            cve_data = create_new_cve_data(rejected_cves[cve_id])

        if cve_data:
            try:
                kernel_sec.issue.validate(cve_data)
            except ValueError as e:
                print('%s: %s' % (announce, e), file=sys.stderr)
                continue
            kernel_sec.issue.save(cve_id, cve_data)
            print(f"Save file issues/{cve_id}.yml")

if __name__ == "__main__":
    main()
