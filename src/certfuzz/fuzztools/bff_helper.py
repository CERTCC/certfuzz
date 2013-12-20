'''
Created on Oct 1, 2010

Contains various methods in support of zzuf.py.

@organization: cert.org
'''
import os
import sys
from ..fuzztools import subprocess_helper as subp
from ..fuzztools import filetools

def set_unbuffered_stdout():
    '''
    Reopens stdout with a buffersize of 0 (unbuffered)
    @rtype: none
    '''
    # reopen stdout file descriptor with write mode
    # and 0 as the buffer size (unbuffered)
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)


# analyze results
def get_crashcount(uniquedir):
    '''
    Counts the number of subdirs found in <uniquedir>.
    Returns the integer count of variants found.
    @rtype: int
    '''
    dirs = [d for d in os.listdir(uniquedir) if os.path.isdir(os.path.join(uniquedir, d))]
    return len(dirs)

def cache_program_once(cfg, seedfile):
    fullpathorig = cfg.full_path_original(seedfile)
    cmdargs = cfg.get_command_list(fullpathorig)
    subp.run_with_timer(cmdargs, cfg.progtimeout * 8, cfg.killprocname, use_shell=True)

def setup_dirs_and_files(cfg_file, cfg):
    # Set up a local fuzzing directory. HGFS or CIFS involves too much overhead, so
    # fuzz locally and then copy over interesting cases as they're encountered
    filetools.make_directories(*cfg.dirs_to_create)

    # Copy seed file and cfg to local fuzzing directory as well as fuzz run output directory
    # TODO: don't think we need this given Seedfile Dir Manager
#    filetools.copy_file(cfg.fullpathseedfile, cfg.fullpathlocalfuzzdir, cfg.output_dir)
    filetools.copy_file(cfg_file, cfg.output_dir)
