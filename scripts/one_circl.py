#!/usr/bin/python3

import requests
import json
import yaml
import sys
import os

def parse_one(cve):
    r = requests.get("https://cve.circl.lu/api/cve/"+cve)
    #print(r.text)
    j = json.loads(r.text)
    #print(j["Published"])
    return j

def translate_one(cve):
    j = parse_one(cve)
    y = {}
    print(cve)
    print(j["summary"])
    print()
    y["description"] = j["summary"]
    y["references"] = j["references"]
    s = yaml.dump(y)
    return s

def write_one(cve):
    s = translate_one(cve)
    n = "./issues/" + cve + ".yml"
    open(n, 'w').write(s)
    os.system("git add "+n)


#cve = "CVE-2008-2544"
for cve in sys.argv[1:]:
    write_one(cve)
