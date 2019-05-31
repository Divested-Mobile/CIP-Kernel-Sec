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
beneath that.  They require PyYAML and html5lib (packaged in Debian as
python3-yaml and python3-html5lib).

Many scripts require access to a kernel git repository.  By default
this is assumed to be in `../kernel`, with remotes named `torvalds`
and `stable` for the mainline and stable repositories.  These can
be overridden by command-line options.

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

* `scripts/cleanup.py` - canonicalise formatting of all issue
files.  This should be run after hand-editing files to reduce
"noise" in later automated updates.

* `scripts/webview.py` - run a local web server that allows browsing
branches and issues.  This requires CherryPy and Jinja2 (packaged
in Debian as python3-cherrypy3 and python3-jinja2).

## Configuration

### Branches

Mainline and official stable branches listed on www.kernel.org are
tracked automatically.  Any additional branches must be configured
specifically, either in `conf/branches.yml` or in
`~/.config/kernel-sec/branches.yml`.  These files, if they exist,
contain a sequence of entries, where each entry is a mapping with the
keys:

* `short_name`: Name used for the branch in issues and in the user
  interface.
* `git_name`: Default git remote name used for the branch.
* `git_branch`: Git remote branch name.
* `base_ver`: Stable version that the branch is based on, e.g.
  "4.4". This needs to be quoted so that it's a string not a
  number.

### Remotes

Remotes must be configured specifically, either in
`conf/remotes.yml` or in `~/.config/kernel-sec/remotes.yml`.
These files, if they exist, contain a mapping where the keys
are default git remote names.  The values are also mappings,
with the keys:

* `commit_url_prefix`: URL prefix for browsing a commit on a
  branch from this remote.
* `git_name`: (optional) The name actually used for this git
  remote, if it's different from the default.

## Contributions

If you have better information about any issue, or additional
unfixed issues, or improvements to the scripts, please send a
merge request.

Note the license information in the [COPYING](COPYING) file.
