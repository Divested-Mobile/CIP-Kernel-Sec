#!/usr/bin/python3

# Copyright 2018 Codethink Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import argparse
import os

import cherrypy
import jinja2

import kernel_sec.branch
import kernel_sec.issue


_template_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader('scripts/templates'),
    autoescape=True)


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

    def __init__(self, name, c_b_map):
        self._name = name
        self._c_b_map = c_b_map

    @cherrypy.expose
    def index(self):
        return self._template.render(
            name=self._name,
            issues=[
                (cve_id, _issue_cache[cve_id])
                for cve_id in sorted(_issue_cache.keys(),
                                     key=kernel_sec.issue.get_id_sort_key)
                if kernel_sec.issue.affects_branch(
                        _issue_cache[cve_id], self._name,
                        self._c_b_map.is_commit_in_branch)
            ])


class Branches:
    _template = _template_env.get_template('branches.html')

    def __init__(self, git_repo, mainline_remote_name, stable_remote_name):
        self._names = kernel_sec.branch.get_live_stable_branches(
            git_repo, stable_remote_name)
        self._names.append('mainline')
        self._c_b_map = kernel_sec.branch.CommitBranchMap(
            git_repo, mainline_remote_name, self._names)

    def _cp_dispatch(self, vpath):
        if len(vpath) == 1 and vpath[0] in self._names:
            return Branch(vpath.pop(), self._c_b_map)
        return vpath

    @cherrypy.expose
    def index(self):
        return self._template.render(names=self._names)


class Issue:
    _template = _template_env.get_template('issue.html')

    def __init__(self, cve_id):
        self._cve_id = cve_id

    @cherrypy.expose
    def index(self):
        return self._template.render(cve_id=self._cve_id,
                                     issue=_issue_cache[self._cve_id])


class Issues:
    _template = _template_env.get_template('issues.html')

    def _cp_dispatch(self, vpath):
        if len(vpath) == 1 and vpath[0] in _issue_cache:
            return Issue(vpath.pop())
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

    def __init__(self, git_repo, mainline_remote_name, stable_remote_name):
        self.branches = Branches(git_repo, mainline_remote_name,
                                 stable_remote_name)
        self.issues = Issues()

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
    parser.add_argument('--mainline-remote',
                        dest='mainline_remote_name', default='torvalds',
                        help='git remote for mainline (default: torvalds)',
                        metavar='NAME')
    parser.add_argument('--stable-remote',
                        dest='stable_remote_name', default='stable',
                        help=('git remote for stable branches '
                              '(default: stable)'),
                        metavar='NAME')
    args = parser.parse_args()

    conf = {
        '/static/style.css': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename':
            os.path.abspath('scripts/templates/style.css')
        }
    }

    cherrypy.quickstart(Root(args.git_repo, args.mainline_remote_name,
                             args.stable_remote_name),
                        '/',
                        conf)
