#!/usr/bin/python3

# Copyright 2017-2018,2020 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

# Report issues affecting each stable branch.

import argparse
import copy
import fnmatch
import subprocess
import re
import sys

import kernel_sec.branch
import kernel_sec.issue
import kernel_sec.version

import yaml

class CustomQuoteDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(CustomQuoteDumper, self).increase_indent(flow, False)

def quoted_presenter(dumper, data):
    if isinstance(data, str):
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')
    return dumper.represent_data(data)

def main(git_repo, remotes, only_fixed_upstream,
         include_ignored, show_description,
         include_fixed, output_format,
         output_filename,
         *branch_names):
    if not branch_names:
        branch_names = ['stable/*']
        if not only_fixed_upstream:
            branch_names.append('mainline')

    live_branches = kernel_sec.branch.get_live_branches(remotes)
    branches = []
    for branch_name in branch_names:
        if '*' in branch_name or '?' in branch_name:
            matched = False
            for branch in live_branches:
                if fnmatch.fnmatch(branch['short_name'], branch_name):
                    branches.append(branch)
                    matched = True
            if not matched:
                print('W: Branch pattern %s did not match any branches'
                      % branch_name,
                      file=sys.stderr)
        else:
            tag = None
            if branch_name[0].isdigit():
                # 4.4 is mapped to stable/4.4
                name = 'stable/' + branch_name
            elif branch_name[0] == 'v':
                # an official tag, e.g. v4.4.92-cip11
                # infer branch from tag (regexp's must be specific)
                for branch in live_branches:
                    if 'tag_regexp' not in branch:
                        # no tag_regexp defined, or mainline
                        continue

                    # predefined in branches.yml or a stable branch
                    if re.match(branch['tag_regexp'], branch_name):
                        tag = branch_name
                        name = branch['short_name']
                        break
                else:
                    raise ValueError('Failed to match tag %r' % branch_name)
            elif ':' in branch_name:
                # a possibly custom tag, e.g. cip/4.19:myproduct-v1
                name, tag = branch_name.split(':', 1)
            else:
                name = branch_name

            for branch in live_branches:
                if branch['short_name'] == name:
                    # there could be multiple tags for the same branch
                    branch_copy = copy.deepcopy(branch)
                    if tag:
                        branch_copy['tag'] = tag
                    branches.append(branch_copy)
                    break
            else:
                msg = "Branch %s could not be found" % branch_name
                raise argparse.ArgumentError(None, msg)

    branches.sort(key=kernel_sec.branch.get_sort_key)

    c_b_map = kernel_sec.branch.CommitBranchMap(git_repo, branches)

    # cache tag commits and set full_name to show the tag
    tag_commits = {}
    for branch in branches:
        if 'tag' in branch:
            start = 'v' + branch['base_ver']
            end = branch['tag']
            tag_commits[end] = set(
                kernel_sec.branch.iter_rev_list(git_repo, end, start))
            branch['full_name'] = ':'.join([branch['short_name'], end])
        else:
            branch['full_name'] = branch['short_name']

    branch_issues = {}
    branch_fixed = {}
    branch_ignored = {}
    issues = set(kernel_sec.issue.get_list())

    for cve_id in issues:
        issue = kernel_sec.issue.load(cve_id)
        ignore = issue.get('ignore', {})
        fixed = issue.get('fixed-by', {})

        # Should this issue be ignored?
        if (not include_ignored and ignore.get('all')) or \
           (only_fixed_upstream and fixed.get('mainline', 'never') == 'never'):
            continue

        for branch in branches:
            branch_name = branch['short_name']

            # Should this issue be ignored for this branch?
            if not include_ignored and ignore.get(branch_name):
                branch_ignored.setdefault(branch['full_name'], []).append(cve_id)
                continue

            # Check if the branch is affected. If not and the issue was fixed
            # on that branch, then make sure the tag contains that fix
            status = kernel_sec.issue.status_on_branch(issue, branch, c_b_map.is_commit_in_branch)
            if kernel_sec.issue.ISSUE_STATUS_NOT_FIXED == status:
                branch_issues.setdefault(
                    branch['full_name'], []).append(cve_id)
            elif 'tag' in branch and fixed:
                if fixed.get(branch_name, 'never') == 'never':
                    if ignore.get(branch_name):
                        branch_ignored.setdefault(branch['full_name'], []).append(cve_id)
                    else:
                        branch_fixed.setdefault(branch['full_name'], []).append(cve_id)

                    continue
                for commit in fixed[branch_name]:
                    if commit not in tag_commits[branch['tag']]:
                        branch_issues.setdefault(
                            branch['full_name'], []).append(cve_id)
                        break
                if branch['full_name'] in branch_issues and \
                    not cve_id in branch_issues[branch['full_name']]:
                        branch_fixed.setdefault(branch['full_name'], []).append(cve_id)
            else:
                branch_fixed.setdefault(branch['full_name'], []).append(cve_id)

    if output_format == 'plain':
        for branch in branches:
            sorted_cve_ids = sorted(
                branch_issues.get(branch['full_name'], []),
                key=kernel_sec.issue.get_id_sort_key)
            if show_description:
                print('%s:' % branch['full_name'])
                for cve_id in sorted_cve_ids:
                    print(cve_id, '=>',
                        kernel_sec.issue.load(cve_id).get('description', 'None'))
            else:
                print('%s:' % branch['full_name'], *sorted_cve_ids)
    elif output_format == 'yaml':
        all_data = {}
        for branch in branches:
            branch_name = branch['full_name']
            sorted_affected_cve_ids = sorted(branch_issues.get(branch_name, []),
                                                key=kernel_sec.issue.get_id_sort_key)
            sorted_fixed_cve_ids = sorted(branch_fixed.get(branch_name, []),
                                                key=kernel_sec.issue.get_id_sort_key)
            sorted_ignored_cve_ids = sorted(branch_ignored.get(branch_name, []),
                                                key=kernel_sec.issue.get_id_sort_key)
            all_data[branch_name] = {
                'affected': sorted_affected_cve_ids,
                'fixed': sorted_fixed_cve_ids,
                'ignored': sorted_ignored_cve_ids,
            }

        yaml.add_representer(str, quoted_presenter, Dumper=CustomQuoteDumper)

        if output_filename is None:
            output = yaml.dump(all_data, Dumper=CustomQuoteDumper, default_flow_style=False)
            print(output)
        else:
            with open(output_filename, "w") as f:
                yaml.dump(all_data, f, Dumper=CustomQuoteDumper, default_flow_style=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Report unfixed CVEs in Linux kernel branches.')
    parser.add_argument('--git-repo',
                        dest='git_repo', default='../kernel',
                        help=('git repository from which to read commit logs '
                              '(default: ../kernel)'),
                        metavar='DIRECTORY')
    parser.add_argument('--remote-name',
                        dest='remote_name', action='append', default=[],
                        help='git remote name mappings, e.g. stable:mystable',
                        metavar='NAME:OTHER-NAME')
    parser.add_argument('--mainline-remote',
                        dest='mainline_remote_name',
                        help="git remote name to use instead of 'torvalds'",
                        metavar='OTHER-NAME')
    parser.add_argument('--stable-remote',
                        dest='stable_remote_name',
                        help="git remote name to use instead of 'stable'",
                        metavar='OTHER-NAME')
    parser.add_argument('--only-fixed-upstream',
                        action='store_true',
                        help='only report issues fixed in mainline')
    parser.add_argument('--include-ignored',
                        action='store_true',
                        help='include issues that have been marked as ignored')
    parser.add_argument('--show-description',
                        action='store_true',
                        help='show the issue description')
    parser.add_argument('branches',
                        nargs='*',
                        help=('specific branch[:tag], branch pattern, '
                              'or stable tag to report on '
                              '(default: stable/*, mainline). '
                              'e.g. stable/4.14 stable/4.4:v4.4.107 '
                              'v4.4.181-cip33 cip/4.19:myproduct-v33'),
                        metavar='[BRANCH[:TAG]|TAG]')
    parser.add_argument('--include-fixed',
                        action='store_true',
                        help='include issues that have been fixed.')
    parser.add_argument('--output-format',
                        dest='output_format',
                        default='plain',
                        help='Output format can be plain/yaml')
    parser.add_argument('--output-filename',
                        dest='output_filename',
                        help='Output file name. This option is enabled if output format is yaml')
    args = parser.parse_args()
    remotes = kernel_sec.branch.get_remotes(args.remote_name,
                                            mainline=args.mainline_remote_name,
                                            stable=args.stable_remote_name)
    kernel_sec.branch.check_git_repo(args.git_repo, remotes)
    main(args.git_repo, remotes, args.only_fixed_upstream,
         args.include_ignored, args.show_description, args.include_fixed, args.output_format, args.output_filename, *args.branches)
