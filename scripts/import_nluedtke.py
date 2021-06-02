#!/usr/bin/python3

import os

class IssueList:
    issues = "./issues/"
    
    def issue(m, cve):
        if os.path.exists(m.issues + cve + ".yml"):
            return True
        return None

class KernelCVE(IssueList):
    kernel_cves = "../linux_kernel_cves"

    def check(m, version):
        path = m.kernel_cves + "/data/" + version + "/" + version + "_CVEs.txt"
        total = 0
        known = 0
        for l in open(path).readlines():
            s = l.split(":")
            cve = s[0]
            total += 1
            if m.issue(cve):
                known += 1
            else:
                print(l)
        print(total-known, "/", total)

        
i = KernelCVE()
i.check("5.10")


