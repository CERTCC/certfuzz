'''
Created on Feb 10, 2014

@organization: cert.org
'''
import logging
import os
from dev.misc import copydir, copyfile, onerror
import shutil
import tempfile
from .prepend_license import main as _prepend_license
from .errors import BuildError
import subprocess


logger = logging.getLogger(__name__)


SUPPORTED_PLATFORMS = {'linux': None,
                     'windows': None,
                     'osx': None,
                     }


class Build(object):
    _blacklist = []
    _common_dirs = ['certfuzz', 'seedfiles']
    _license_file = 'COPYING.txt'

    def __init__(self, platform=None, distpath=None, srcpath=None):
        self.platform = platform

        if distpath == None:
            self.base_path = os.path.abspath(os.path.dirname(__file__))
        else:
            self.base_path = os.path.abspath(distpath)

        if srcpath == None:
            self.src_path = os.path.abspath(os.path.join(self.base_path, '../../src'))
        else:
            self.src_path = os.path.abspath(srcpath)

        self.tmpdir = None
#
#        self.dev_builds_path = os.path.abspath(os.path.join(self.src_path, '..', 'dev_builds'))
#        self.target_path = os.path.abspath(os.path.join(self.dev_builds_path, self.name))
        self.platform_path = os.path.join(self.src_path, self.platform)
        self._in_runtime_context = False
        self._filename_pfx = 'BFF-{}'.format(self.platform)
        self.zipfile = '{}.zip'.format(self._filename_pfx)

    def __enter__(self):
        logger.debug('Entering Build context')
        self.tmpdir = tempfile.mkdtemp(prefix='bff_build_{}_'.format(self.platform))
        logger.debug('Temp dir is %s', self.tmpdir)
        self._in_runtime_context = True
        return self

    def __exit__(self, etype, value, traceback):
        logger.debug('Removing temp dir %s', self.tmpdir)
        shutil.rmtree(self.tmpdir)
        self._in_runtime_context = False

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

    def export(self):
        logger.info('Exporting')
        logger.info('Copy platform-specific files to tmpdir')
        self._copy_platform()

        logger.info('Copy common files to tmpdir')
        self._copy_common_dirs()

    def prune(self):
        logger.info('Pruning')
        logger.debug('nothing really happened here')

    def refine(self):
        logger.info('Refining')
        logger.info('Set up results dir')
        self._create_results_dir()

        logger.info('Clean up build tmpdir')
        self._clean_up(self.tmpdir, remove_blacklist=False)

    def prepend_license(self):
        '''
        Adds the license text to the code prior to packaging
        '''
        logger.info('Prepending License to *.py')
        lf = os.path.join(self.tmpdir, self._license_file)
        _prepend_license(license_file=lf,
                         basedir=self.tmpdir,
                         remove=False,
                         add=True,
                         debug=False,
                         overwrite=True,
                         )

    def package(self):
        '''
        Creates a zip file containing the code
        '''
        logger.info('Packaging')
        if self.zipfile:
            zipfile_base = self.zipfile
        else:
            raise BuildError('Unable to determine zipfile name')

        export_dir = self.tmpdir
        fd, tmpzip = tempfile.mkstemp(prefix='{}-'.format(self._filename_pfx),
                                  suffix='.zip')
        os.close(fd)


        import zipfile

        def _zipdir(path, zip):
            cwd = os.getcwd()
            os.chdir(path)
            for root, dirs, files in os.walk('.'):
                for file in files:
                    zip.write(os.path.join(root, file))
            os.chdir(cwd)

        with zipfile.ZipFile(tmpzip, 'w') as zipf:
            _zipdir(export_dir, zipf)

#        args = ['zip', '-r', '-v', tmpzip, '.']
#        logger.debug('shell: {}'.format(' '.join(args)))
#        subprocess.call(args, cwd=export_dir)

        target = os.path.join(self.base_path, zipfile_base)
        if os.path.exists(target):
            os.remove(target)

        logger.debug('moving {} to {}'.format(tmpzip, target))
        shutil.move(tmpzip, target)

        _perm = 0644
        logger.debug('setting {:04o} permissions on {}'.format(_perm, target))
        os.chmod(target, _perm)

    def _copy_platform(self):
        # copy platform-specific content
        for f in os.listdir(self.platform_path):
            f_src = os.path.join(self.platform_path, f)

            # blacklist files and dirs by name
            # these files will not be copied
            if f in self._blacklist:
                logger.info('Skipping path (blacklisted) %s', f_src)
                continue

            f_dst = os.path.join(self.tmpdir, f)
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
            d_dst = os.path.join(self.tmpdir, d)
            copydir(d_src, d_dst)

    def _create_results_dir(self):
        # create result dir if it doesn't exist, otherwise don't touch it
        result_path = os.path.join(self.tmpdir, 'results')
        if not os.path.exists(result_path):
            logger.info('Result path does not exist, creating %s', result_path)
            os.makedirs(result_path)
        else:
            logger.info('Result path %s already exists, proceeding', result_path)

    def _clean_up(self, path, remove_blacklist=True):
        logger.debug("Cleaning up %s", path)
        for f in os.listdir(path):
            fpath = os.path.join(path, f)
            if os.path.isdir(fpath):
                if f in self._blacklist:
                    logger.info('Removing %s dir from %s', f, path)
                    shutil.rmtree(fpath, ignore_errors=False, onerror=onerror)
                else:
                    self._clean_up(fpath, remove_blacklist=True)
