'''
Created on September 1, 2016

@organization: cert.org
'''
import logging
import tempfile
import os
import time
import shutil
from distutils import dir_util

from subprocess import Popen

use_pygit = True

try:
    from certfuzz.fuzztools.filetools import rm_rf, best_effort_move
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    import sys
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.fuzztools.filetools import rm_rf, best_effort_move


try:
    from git import Repo
except ImportError:
    use_pygit = False


logger = logging.getLogger()
logger.setLevel(logging.WARNING)


def copydir(src, dst):
    logger.info('Copy dir  %s -> %s', src, dst)
    dir_util.copy_tree(src, dst)


def copyfile(src, dst):
    logger.info('Copy file %s -> %s', src, dst)
    shutil.copy(src, dst)


def main():
    from optparse import OptionParser

    branch = 'develop'
    target_path = '.'

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    usage = "usage: %prog [options] fuzzedfile"
    parser = OptionParser(usage)
    parser.add_option('-d', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages (overrides --verbose)')
    parser.add_option('-m', '--master', dest='master',
                      action='store_true', help='Use master branch instead of develop')
    parser.add_option('-f', '--force', dest='force',
                      action='store_true', help='Force update')
    parser.add_option('-y', '--yes', dest='yes',
                      action='store_true', help='Don\'t ask questions')
    parser.add_option('-s', '--save', dest='save',
                      action='store_true', help='Save original certfuzz directory')

    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if options.master:
        branch = 'master'

    logger.debug('Using %s branch' % branch)

    tempdir = tempfile.mkdtemp()
    if use_pygit:
        repo = Repo.clone_from(
            'https://github.com/CERTCC-Vulnerability-Analysis/certfuzz.git', tempdir, branch=branch)
        headcommit = repo.head.commit
        logger.info('Cloned certfuzz version %s' % headcommit.hexsha)
        logger.info('Last modified %s' % time.strftime(
            "%a, %d %b %Y %H:%M", time.gmtime(headcommit.committed_date)))

    if options.save:
        logger.info('Saving original certfuzz directory as certfuzz.bak')
        os.rename('certfuzz', 'certfuzz.bak')
    else:
        rm_rf('certfuzz')
        logger.info('Deleting certfuzz directory...')

    logger.debug('Moving certfuzz directory from git clone...')
    best_effort_move(os.path.join(tempdir, 'src', 'certfuzz'), target_path)

    logger.debug('Moving linux-specific files from git clone...')
    platform_path = os.path.join(tempdir, 'src', 'linux')

    # copy platform-specific content
    for f in os.listdir(platform_path):
        f_src = os.path.join(platform_path, f)

        f_dst = os.path.join(target_path, f)
        if os.path.isdir(f_src):
            copydir(f_src, f_dst)
        elif os.path.isfile(f_src):
            copyfile(f_src, f_dst)
        else:
            logger.warning("Not sure what to do with %s", f_src)


if __name__ == '__main__':
    main()
