# kernel-sec - Linux kernel CVE tracker

This project tracks the status of security issues, identified by CVE
ID, in mainline and in stable branches.

## Issue format

Issues are stored in YAML format files in the `issues` subdirectory.
The schema is roughly documented in
[issues/template.yml](issues/template.yml) and is validated by the
`kernel_sec.validate` module.

## Scripts

Various scripts, written in Python 3, are in the `scripts`
subdirectory.  Supporting modules are in the `kernel_sec` subdirectory
beneath that.

* `scripts/import_debian.py` - import information from Debian's
`kernel_sec` project.  It includes all issues that Debian considers
active or that are already tracked here.

* `scripts/import_ubuntu.py` - import information from Ubuntu's
`ubuntu-cve-tracker` project.  It includes issues that Ubuntu
marked as affecting the 'linux' package and don't have the word
'Android' in the description, and that are either dated from the
current or previous year or that are already tracked here.

* `scripts/import_stable.py` - import information about backports
to stable by reading the git commit logs.

* `scripts/report_affected.py` - report which issues affect the
specified branches, or all active branches.

* `scripts/validate.py` - validate all issue files against the
schema.

## Contributions

If you have better information about any issue, or additional
unfixed issues, or improvements to the scripts, please send a
pull request.

Note the license information in the [COPYING](COPYING) file.
