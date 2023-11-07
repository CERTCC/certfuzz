'''
Created on Feb 11, 2014

@author: adh
'''
import os
import shutil
import tempfile
import logging
import zipfile
from git import git_rev, git_hash

from devmods.misc import copydir, copyfile, onerror, mdtotextfile

from .prepend_license import main as _prepend_license
from subprocess import CalledProcessError

logger = logging.getLogger(__name__)


def _zipdir(path, zip_):
    cwd = os.getcwd()
    os.chdir(path)
    for root, _dirs, files in os.walk('.'):
        for f in files:
            zip_.write(os.path.join(root, f))
        if not files and not _dirs:
            # Include empty directories as well
            zip_.write(root, compress_type=zipfile.ZIP_STORED)
    os.chdir(cwd)


class Build(object):
    _blocklist = []
    _common_dirs = ['certfuzz', 'seedfiles', 'tools']
    _license_file = 'COPYING.txt'

    def __init__(self, platform=None, distpath=None, srcpath=None):
        self.platform = platform

        if distpath == None:
            self.base_path = os.path.abspath(os.path.dirname(__file__))
        else:
            self.base_path = os.path.abspath(distpath)

        if srcpath == None:
            self.src_path = os.path.abspath(
                os.path.join(self.base_path, '../../src'))
        else:
            self.src_path = os.path.abspath(srcpath)

        self.tmp_dir = None
        self.build_dir = None
        self.platform_path = os.path.join(self.src_path, self.platform)
        self._in_runtime_context = False
        self._filename_pfx = 'BFF-{}'.format(self.platform)
        self.zipfile = '{}.zip'.format(self._filename_pfx)
        self.target = os.path.join(self.base_path, self.zipfile)
        self.license_md_path = os.path.join(self.src_path, '..', 'LICENSE.md')
        self.license_txt_path = os.path.join(
            self.platform_path, self._license_file)

    def __enter__(self):
        logger.debug('Entering Build context')
        self.tmp_dir = tempfile.mkdtemp(
            prefix='bff_build_{}_'.format(self.platform))
        logger.debug('Temp dir is %s', self.tmp_dir)
        self.build_dir = os.path.join(self.tmp_dir, 'bff')
        os.mkdir(self.build_dir)
        self._in_runtime_context = True
        return self

    def __exit__(self, etype, value, traceback):
        handled = False
        if etype is CalledProcessError:
            logger.debug('Error returned from called processs: %s' % value)
        logger.debug('Removing temp dir %s', self.tmp_dir)
        shutil.rmtree(self.tmp_dir)
        self._in_runtime_context = False

        return handled

    def build(self):
        '''
        Perform a build. Must be invoked using with Build(foo)... syntax
        '''
        assert self._in_runtime_context, 'Build() must be invoked using with... syntax'
        self.export()
        self.prune()
        self.refine()
        self.prepend_license()
        self.package()

    def _convert_md_files(self):
        mdtotextfile(self.license_md_path, self.license_txt_path)

    def export(self):
        logger.info('Exporting')
        logger.info('Copy platform-specific files to tmp_dir')
        self._copy_platform()

        logger.info('Copy common files to tmp_dir')
        self._copy_common_dirs()

        logger.info('Getting git revision')
        self.git_rev = git_rev()
        self.git_hash = git_hash()
        logger.info('%s : %s' % (self.git_rev, self.git_hash))

    def prune(self):
        logger.info('Pruning')
        logger.debug('nothing really happened here')

    def refine(self):
        logger.info('Refining')
        logger.info('Set up results dir')
        self._create_results_dir()
        logger.info('Clean up build tmp_dir')
        self._clean_up(self.build_dir, remove_blocklist=False)

    def prepend_license(self):
        '''
        Adds the license text to the code prior to packaging
        '''
        logger.info('Prepending License to *.py')
        lf = os.path.join(self.build_dir, self._license_file)
        _prepend_license(license_file=lf,
                         basedir=self.build_dir,
                         remove=False,
                         add=True,
                         debug=False,
                         overwrite=True,
                         )

    def package(self):
        logger.info('Packaging')

    def _move_to_target(self, tmpzip):
        if os.path.exists(self.target):
            os.remove(self.target)
        logger.debug('moving {} to {}'.format(tmpzip, self.target))
        shutil.move(tmpzip, self.target)
        _perm = 0644
        logger.debug(
            'setting {:04o} permissions on {}'.format(_perm, self.target))
        os.chmod(self.target, _perm)

    def _create_zip(self):
        fd, tmpzip = tempfile.mkstemp(prefix='{}-'.format(self._filename_pfx),
                                      suffix='.zip',
                                      dir=self.tmp_dir)
        os.close(fd)

        with zipfile.ZipFile(tmpzip, 'w') as zipf:
            _zipdir(self.build_dir, zipf)
        return tmpzip

    def _copy_platform(self):
        if os.path.isdir(self.platform_path):
            platform_path = self.platform_path
        else:
            logger.info(
                'No platform-specific info found at %s', self.platform_path)
            platform_path = os.path.join(self.src_path, 'linux')
            logger.info('Defaulting to %s', platform_path)
            # Set license text path since we're overriding it above
            self.license_txt_path = os.path.join(
                platform_path, self._license_file)

        logger.info('Converting markdown files')
        self._convert_md_files()

        # copy platform-specific content
        for f in os.listdir(platform_path):
            f_src = os.path.join(platform_path, f)

            # blocklist files and dirs by name
            # these files will not be copied
            if f in self._blocklist:
                logger.info('Skipping path (blocklisted) %s', f_src)
                continue

            f_dst = os.path.join(self.build_dir, f)
            if os.path.isdir(f_src):
                copydir(f_src, f_dst)
            elif os.path.isfile(f_src):
                copyfile(f_src, f_dst)
            else:
                logger.warning("Not sure what to do with %s", f_src)

    def _copy_common_dirs(self):
        # copy other dirs
        for d in self._common_dirs:
            d_src = os.path.join(self.src_path, d)
            d_dst = os.path.join(self.build_dir, d)
            copydir(d_src, d_dst)

    def _create_results_dir(self):
        # create result dir if it doesn't exist, otherwise don't touch it
        result_path = os.path.join(self.build_dir, 'results')
        if not os.path.exists(result_path):
            logger.info('Result path does not exist, creating %s', result_path)
            os.makedirs(result_path)
        else:
            logger.info(
                'Result path %s already exists, proceeding', result_path)

    def _clean_up(self, path, remove_blocklist=True):
        for f in os.listdir(path):
            fpath = os.path.join(path, f)
            if os.path.isdir(fpath):
                if f in self._blocklist:
                    logger.info('Removing %s dir from %s', f, path)
                    shutil.rmtree(fpath, ignore_errors=False, onerror=onerror)
                else:
                    self._clean_up(fpath, remove_blocklist=True)
