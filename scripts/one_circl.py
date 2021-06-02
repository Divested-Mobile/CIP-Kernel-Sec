#!/usr/bin/python3

import requests
import json
import yaml
import sys

def parse_one(cve):
    r = requests.get("https://cve.circl.lu/api/cve/"+cve)
    #print(r.text)
    j = json.loads(r.text)
    #print(j["Published"])
    return j

def translate_one(cve):
    j = parse_one(cve)
    y = {}
    print(j["summary"])
    y["description"] = j["summary"]
    y["references"] = j["references"]
    s = yaml.dump(y)
    return s

def write_one(cve):
    s = translate_one(cve)
    n = "./issues/" + CVE + ".yml"
    open(n).write(s)
    os.system("git add "+n)


#cve = "CVE-2008-2544"
cve = sys.argv[1]
translate_one(cve)
