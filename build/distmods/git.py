'''
Created on Jun 20, 2014

@author: wd
'''
import subprocess


def git_hash():
    args = ['git', 'rev-parse', 'HEAD']
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    for l in p.communicate()[0].splitlines():
        if not l:
            continue
        return l[:7]


def git_rev():
    args = ['git', 'rev-list', 'HEAD']
    revcount = 0
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    for l in p.communicate()[0].splitlines():
        if not l:
            continue
        revcount += 1
    return revcount
