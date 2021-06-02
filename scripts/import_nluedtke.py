#!/usr/bin/python3

import os

class IssueList:
    pass

class KernelCVE(IssueList):
    kernel_cves = "../linux_kernel_cves"

    def check(m, version):
        path = m.kernel_cves + "/data/" + version + "/" + version + "_CVEs.txt"
        for l in open(path).readlines():
            s = l.split(":")
            print(s[0], s[1])
        
i = KernelCVE()
i.check("5.10")


