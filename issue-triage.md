# Triaging kernel security issues

The import scripts can automatically fill in much of the important
information about security issues, but sometimes you will need to
manually fill in details.  This document describes how to do that,
specifically to record that issues don't affect some or all branches.

## Check that the issue is valid

Anyone can apply to MITRE to assign a CVE ID, and MITRE does not
verify that the security issues are real.  In some cases,
inexperienced security researchers request CVE IDs for bugs that look
like security issues, but are not.

For example, a potential null pointer dereference that can be
triggered by an unprivileged user would be a denial-of-service
vulnerability.  However, if it can only be triggered by a user with
the global CAP\_SYS\_ADMIN capability then it is not a security issue
because a user with that capability can already shut down the system.

If the issue is not valid, mark it to be ignored for all branches
and add a comment explaining why:

    comments:
      your-short-name: |-
        This is invalid because …
    …
    ignore:
      all: Invalid

## Identify how the issue was introduced

If the import scripts did not fill in the "introduced-by" field
for an issue, you should try to fill it in yourself, so that it's
known which branches are affected.

If a fix is available, its commit message should include a "Fixes"
trailer that specifies the commit that introduced the issue.  This is
*usually*, but not always, accurate.  You should review the specified
commit and decide for yourself whether it really introduced the issue
or whether the issue already existed in the previous version of the
file(s).  Also check that it is an upstream commit (output of `git
rev-list torvalds/master..`*commit-id* should be empty).  In case it
is a commit on a stable branch, use the corresponding upstream commit
ID instead.

**TODO:** What if multiple commits are identified?

If a fix is available, but it doesn't include a "Fixes" trailer or you
decided that the specified commit was wrongly identified, you will
need to review the git history.  First make sure that you understand
where the bug was located, i.e. which function(s) and file(s) were
incorrect.  Then use `git log -p`, possibly with the `-L` option, to
view changes in those locations.  When you find a commit that appears
to introduce the bug, make sure to review the complete diff to check
whether the bug was really new, or if it already existed in some other
source location.  If it already existed, you need to look further back
in the history of that other source location.

In some cases, the code that needs to be fixed was correct when
originally introduced but became incorrect later because of an API
change.  For example, it might have originally handled the two
possible values of a parameter, but later on a third possible value
was added.  In that case the "introduced-by" commit should be the one
that made the API change.

If the issue existed since the beginning of git history for the kernel
(Linux 2.6.12-rc2), you should use that commit as the "introduced-by"
commit.  Do *not* use commit IDs for older versions that are in
converted repositories, as this may cause problems for other users
that have not added those as remotes.

Sometimes the commit that introduced the issue will have been
backported to stable branches.  Use `scripts/import_stable.py` to
fill in information about those backports.

## Check the kernel configurations

For CIP kernel branches, you can check in the
[cip-kernel-config](https://gitlab.com/cip-project/cip-kernel/cip-kernel-config)
repository whether the affected feature or source files are actually
used by members.  If they are not used on a given branch, you can mark
the issue to be ignored for that branch.

Remember that the source files might have been renamed since a branch
was created.  For example, if there is an issue in `tx.c` in the iwlwifi
driver, you can check whether that was renamed between linux-4.4.y-cip
and upstream by running:

    git log --summary --full-diff --reverse cip/linux-4.4.y-cip..torvalds/master \
        -- drivers/net/wireless/intel/iwlwifi/pcie/tx.c

You can then see at the top of the log that the first commit to this
filename renamed multiple source files, and what the old name for this
file was:

     rename drivers/net/wireless/{ => intel}/iwlwifi/pcie/tx.c (100%)

