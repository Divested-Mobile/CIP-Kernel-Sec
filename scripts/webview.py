#!/usr/bin/python3

# Copyright 2018-2020 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import argparse
import os
import re
import urllib.parse

import cherrypy
import jinja2
import markupsafe

import kernel_sec.branch
import kernel_sec.issue


# Match host part and either query part or last path part
_URL_ABBREV_RE = re.compile(
    r'^https?://([^/]*/?)(?:([^?]*)(\?.*)|(.*?)(/[^/]*/?))$')


def _url_abbrev(value):
    match = _URL_ABBREV_RE.match(value)
    if not match:
        return value
    elif match.group(2) and match.group(3):
        return match.expand(r'\1…\3')
    elif match.group(4) and match.group(5):
        return match.expand(r'\1…\5')
    else:
        return match.expand(r'\1\3\5')


_LINKIFY_RE = re.compile(r'\b(?P<label>'
                         r'(?P<url>https?://[^>\)\]"\s]+)'
                         r'|(?P<issue>CVE-[-0-9]+)\b'
                         r'|(?P<commit>[0-9a-f]{7,})\b'
                         r')')


@jinja2.evalcontextfilter
def _linkify(context, value):
    from markupsafe import escape, Markup

    results = []
    pos = 0

    # Create links for link-ish text and escape everything else
    for match in _LINKIFY_RE.finditer(value):
        results.append(escape(value[pos:match.start()]))
        pos = match.end()
        if match.group('url'):
            url = match.group('url')
        elif match.group('issue'):
            url = '/issue/%s/' % match.group('issue')
        else:
            url = _LINKIFY_COMMIT_PREFIX + match.group('commit')
        results.append('<a href="%s">%s</a>'
                       % (escape(url), escape(match.group('label'))))
    results.append(escape(value[pos:]))

    # Concatenate, and inhibit auto-escaping if necessary
    result = ''.join(results)
    if context.autoescape:
        result = Markup(result)
    return result


_template_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader('scripts/templates'),
    autoescape=True)
_template_env.filters['urlabbrev'] = _url_abbrev
_template_env.filters['linkify'] = _linkify


class IssueCache:
    def __init__(self):
        self._data = {}

    def _refresh(self, name, loader):
        file_time = os.stat(name).st_mtime
        cache_data, cache_time = self._data.get(name, (None, None))
        if file_time != cache_time:
            cache_data, cache_time = loader(), file_time
            self._data[name] = (cache_data, cache_time)
        return cache_data

    def _refresh_keys(self):
        return self._refresh('issues',
                             lambda: set(kernel_sec.issue.get_list()))

    def _refresh_issue(self, cve_id):
        filename = kernel_sec.issue.get_filename(cve_id)
        return self._refresh(filename,
                             lambda: kernel_sec.issue.load_filename(filename))

    def keys(self):
        return iter(self._refresh_keys())

    def __contains__(self, cve_id):
        return cve_id in self._refresh_keys()

    def __getitem__(self, cve_id):
        if cve_id not in self._refresh_keys():
            raise KeyError
        return self._refresh_issue(cve_id)


_issue_cache = IssueCache()


class Branch:
    _template = _template_env.get_template('branch.html')

    def __init__(self, name, root):
        self._name = name
        self._root = root

    @cherrypy.expose
    def index(self):
        return self._template.render(
            name=self._name,
            issues=[
                (cve_id, _issue_cache[cve_id])
                for cve_id in sorted(_issue_cache.keys(),
                                     key=kernel_sec.issue.get_id_sort_key)
                if kernel_sec.issue.affects_branch(
                        _issue_cache[cve_id],
                        self._root.branch_defs[self._name],
                        self._root.is_commit_in_branch)
            ])


class Branches:
    _template = _template_env.get_template('branches.html')

    def __init__(self, root):
        self._root = root

    def _cp_dispatch(self, vpath):
        if len(vpath) == 1:
            branch_name = urllib.parse.unquote(vpath[0])
            if branch_name in self._root.branch_names:
                return Branch(branch_name, self._root)
        return vpath

    @cherrypy.expose
    def index(self):
        return self._template.render(names=self._root.branch_names)


class Issue:
    _template = _template_env.get_template('issue.html')

    def __init__(self, cve_id, root):
        self._cve_id = cve_id
        self._root = root

    @cherrypy.expose
    def index(self):
        issue = _issue_cache[self._cve_id]
        return self._template.render(
            cve_id=self._cve_id,
            issue=issue,
            branches=[
                (self._root.branch_defs[branch_name],
                 kernel_sec.issue.affects_branch(
                     issue, self._root.branch_defs[branch_name],
                     self._root.is_commit_in_branch))
                for branch_name in self._root.branch_names
            ],
            remotes=self._root.remotes)


class OpenIssues:
    _template = _template_env.get_template('open_issues.html')

    def __init__(self, root):
        self._root = root

    @cherrypy.expose
    def index(self):
        open_cve_ids = []
        branches = [
            (branch_name, self._root.branch_defs[branch_name], {})
            for branch_name in self._root.branch_names
        ]
        for cve_id in _issue_cache.keys():
            issue = _issue_cache[cve_id]
            ignore = issue.get('ignore', {})
            if 'all' in ignore:
                continue
            is_open = False
            for branch_name, branch, affected in branches:
                if kernel_sec.issue.affects_branch(
                        issue, branch, self._root.is_commit_in_branch):
                    affected[cve_id] = True
                    if branch_name not in ignore:
                        is_open = True
            if is_open:
                open_cve_ids.append(cve_id)

        return self._template.render(
            cve_ids=[
                (cve_id, _issue_cache[cve_id])
                for cve_id in sorted(open_cve_ids,
                                     key=kernel_sec.issue.get_id_sort_key)
            ],
            branches=branches)


class Issues:
    _template = _template_env.get_template('issues.html')

    def __init__(self, root):
        self._root = root

    def _cp_dispatch(self, vpath):
        if len(vpath) == 1 and vpath[0] in _issue_cache:
            return Issue(vpath.pop(), self._root)
        if len(vpath) == 1 and vpath[0] == 'open':
            return OpenIssues(self._root)
        return vpath

    @cherrypy.expose
    def index(self):
        return self._template.render(
            cve_ids=[
                (cve_id, _issue_cache[cve_id])
                for cve_id in sorted(_issue_cache.keys(),
                                     key=kernel_sec.issue.get_id_sort_key)
            ])


class Root:
    _template = _template_env.get_template('root.html')

    def __init__(self, git_repo, remotes):
        self.remotes = remotes

        branch_defs = kernel_sec.branch.get_live_branches()
        self.branch_names = [
            branch['short_name']
            for branch in sorted(branch_defs,
                                 key=kernel_sec.branch.get_sort_key)
        ]
        self.branch_defs = {
            branch['short_name']: branch for branch in branch_defs
        }

        c_b_map = kernel_sec.branch.CommitBranchMap(
            git_repo, remotes, branch_defs)
        self.is_commit_in_branch = c_b_map.is_commit_in_branch

        self.branches = Branches(self)
        self.issues = Issues(self)

    def _cp_dispatch(self, vpath):
        if vpath[0] == 'branch':
            vpath.pop(0)
            return self.branches
        if vpath[0] == 'issue':
            vpath.pop(0)
            return self.issues
        return vpath

    @cherrypy.expose
    def index(self):
        return self._template.render()


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
    parser.add_argument('--host',
                        dest='hostname', default='127.0.0.1',
                        help="hostname on which web server runs",
                        metavar='HOSTNAME')
    parser.add_argument('--port',
                        dest='port', default=8080, type=int,
                        help="port on which web server runs",
                        metavar='PORT')
    args = parser.parse_args()
    remotes = kernel_sec.branch.get_remotes(args.remote_name,
                                            mainline=args.mainline_remote_name,
                                            stable=args.stable_remote_name)
    _LINKIFY_COMMIT_PREFIX = remotes['stable']['commit_url_prefix']
    kernel_sec.branch.check_git_repo(args.git_repo, remotes)

    conf = {
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.abspath('scripts/static')
        }
    }

    cherrypy.config.update({
        'server.socket_host': args.hostname,
        'server.socket_port': args.port,
        })

    cherrypy.quickstart(Root(args.git_repo, remotes),
                        '/',
                        conf)
