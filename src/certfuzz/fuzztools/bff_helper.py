'''
Created on Oct 1, 2010

Contains various methods in support of zzuf.py.

@organization: cert.org
'''
import os


# analyze results
def get_crashcount(uniquedir):
    '''
    Counts the number of subdirs found in <uniquedir>.
    Returns the integer count of variants found.
    @rtype: int
    '''
    dirs = [d for d in os.listdir(uniquedir) if os.path.isdir(os.path.join(uniquedir, d))]
    return len(dirs)
