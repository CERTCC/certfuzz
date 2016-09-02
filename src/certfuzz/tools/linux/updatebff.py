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

from subprocess import call, check_output
from __builtin__ import False

from certfuzz.fuzztools.filetools import rm_rf, best_effort_move

logger = logging.getLogger()
logger.setLevel(logging.WARNING)


def copydir(src, dst):
    logger.debug('Copy dir  %s -> %s', src, dst)
    dir_util.copy_tree(src, dst)


def copyfile(src, dst):
    logger.debug('Copy file %s -> %s', src, dst)
    shutil.copy(src, dst)


def main():
    from optparse import OptionParser

    branch = 'develop'
    target_path = '.'
    blacklist = ['configs']
    certfuzz_dir = os.path.join(target_path, 'certfuzz')

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

    logger.info('Using %s branch' % branch)

    tempdir = git_update(branch=branch)

    if options.save:
        logger.debug('Saving original certfuzz directory as certfuzz.bak')
        os.rename(certfuzz_dir, '%s.bak' % certfuzz_dir)
    else:
        rm_rf(certfuzz_dir)
        logger.debug('Deleting certfuzz directory...')

    logger.info('Moving certfuzz directory from git clone...')
    copydir(os.path.join(tempdir, 'src', 'certfuzz'),
            os.path.join(target_path, 'certfuzz'))

    logger.info('Moving linux-specific files from git clone...')
    platform_path = os.path.join(tempdir, 'src', 'linux')

    # copy platform-specific content
    for f in os.listdir(platform_path):
        if f in blacklist:
            logger.debug('Skipping %s' % f)
            continue
        f_src = os.path.join(platform_path, f)

        f_dst = os.path.join(target_path, f)
        if os.path.isdir(f_src):
            copydir(f_src, f_dst)
        elif os.path.isfile(f_src):
            copyfile(f_src, f_dst)
        else:
            logger.warning("Not sure what to do with %s", f_src)

    logger.debug('Removing %s' % tempdir)
    rm_rf(tempdir)


def git_update(uri='https://github.com/CERTCC-Vulnerability-Analysis/certfuzz.git', branch='develop'):

    use_pygit = True

    try:
        from git import Repo
    except ImportError:
        use_pygit = False

    tempdir = tempfile.mkdtemp()

    if use_pygit:
        repo = Repo.clone_from(uri, tempdir, branch=branch)
        headcommit = repo.head.commit
        headversion = headcommit.hexsha
        gitdate = time.strftime(
            "%a, %d %b %Y %H:%M", time.gmtime(headcommit.committed_date))
    else:
        ret = call(['git', 'clone', uri, tempdir, '--branch', branch])
        print('ret: %d' % ret)
        headversion = check_output(['git', 'rev-parse', 'HEAD'], cwd=tempdir)
        gitdate = check_output(
            ['git', 'log', '-1', '--pretty=format:%cd'], cwd=tempdir)

    logger.info('Cloned certfuzz version %s' % headversion)
    logger.info('Last modified %s' % gitdate)

    return tempdir


if __name__ == '__main__':
    main()
