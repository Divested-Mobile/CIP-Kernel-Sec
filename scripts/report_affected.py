#!/usr/bin/python3

# Report issues affecting each stable branch.

import io
import subprocess
import sys

import kernel_sec.branch, kernel_sec.issue, kernel_sec.version

def get_commits(git_repo, end, start=None):
    if start:
        list_expr = '%s..%s' % (start, end)
    else:
        list_expr = end

    list_proc = subprocess.Popen(['git', 'rev-list', list_expr],
                                 cwd=git_repo, stdout=subprocess.PIPE)
    for line in io.TextIOWrapper(list_proc.stdout):
        yield line.rstrip('\n')

def main(git_repo='../kernel', mainline_remote_name='torvalds',
         stable_remote_name='stable', *branch_names):
    if branch_names:
        # Support stable release strings as shorthand for stable branches
        branch_names = [kernel_sec.branch.get_base_ver_stable_branch(name)
                        if name[0].isdigit() else name
                        for name in branch_names]
    else:
        branch_names = kernel_sec.branch.get_live_stable_branches(
                           git_repo, stable_remote_name) \
                       + ['mainline']

    # Generate sort key for each branch
    branch_sort_key = {}
    for branch in branch_names:
        if branch == 'mainline':
            branch_sort_key[branch] = [1000000]
        else:
            base_ver = kernel_sec.branch.get_stable_branch_base_ver(branch)
            assert base_ver is not None
            branch_sort_key[branch] = kernel_sec.version.get_sort_key(base_ver)

    # Generate sort key for each commit
    commit_sort_key = {}
    start = None
    for branch in sorted(branch_names,
                         key=(lambda branch: branch_sort_key[branch])):
        if branch == 'mainline':
            end = '%s/master' % mainline_remote_name
        else:
            base_ver = kernel_sec.branch.get_stable_branch_base_ver(branch)
            assert base_ver is not None
            end = 'v' + base_ver
        for commit in get_commits(git_repo, end, start):
            commit_sort_key[commit] = branch_sort_key[branch]
        start = end

    branch_issues = {}
    issues = set(kernel_sec.issue.get_list())

    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)

        for branch in branch_names:
            # If it was not introduced on this branch, and was introduced on
            # mainline after the branch point, branch is not affected
            introduced = issue.get('introduced-by')
            if introduced and branch not in introduced \
               and 'mainline' in introduced:
                for commit in introduced['mainline']:
                    if commit in commit_sort_key \
                       and commit_sort_key[commit] <= branch_sort_key[branch]:
                        break
                else:
                    continue

            # If it was fixed on this branch, or fixed on mainline before
            # the branch point, branch is not affected
            fixed = issue.get('fixed-by')
            if fixed:
                if branch in fixed:
                    continue
                if 'mainline' in fixed:
                    for commit in fixed['mainline']:
                        if commit not in commit_sort_key \
                           or commit_sort_key[commit] > branch_sort_key[branch]:
                            break
                    else:
                        continue

            branch_issues.setdefault(branch, []).append(cve_id)

    for branch in branch_names:
        print('%s: %s' % (branch, ' '.join(branch_issues.get(branch, []))))

if __name__ == '__main__':
    main(*sys.argv[1:])
