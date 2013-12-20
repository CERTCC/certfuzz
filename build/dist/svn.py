'''
Created on Dec 9, 2013

@author: adh
'''
import subprocess


def svn_export(src, dst):
    args = ['svn', 'export', src, dst]
    subprocess.call(args)


def svn_rev(url):
    args = ['svn', 'info', url]
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    for l in p.communicate()[0].splitlines():
        if not l:
            continue
        k, v = [x.strip() for x in l.split(':', 1)]
        if k == "Revision":
            return v
