'''
Created on Dec 9, 2013

@author: adh
'''
import os

import logging
import shutil
from devmods.misc import copydir, copyfile, onerror, mdtotextfile

logger = logging.getLogger(__name__)


class Build(object):
    _common_dirs = ['certfuzz', 'seedfiles', 'tools']
    _blocklist = ['.svn']
    _name = None
    _platform = None

    def __init__(self, name=None, platform=None):
        if name:
            self.name = name
        else:
            self.name = self._name

        if platform:
            self.platform = platform
        else:
            self.platform = self._platform

        self.my_path = os.path.abspath(os.path.dirname(__file__))
        self.src_path = os.path.abspath(
            os.path.join(self.my_path, '../../src'))
        self.dev_builds_path = os.path.abspath(
            os.path.join(self.src_path, '..', 'dev_builds'))

        target_shortname = '{}-{}'.format(self.name, self.platform)

        self.target_path = os.path.abspath(
            os.path.join(self.dev_builds_path, target_shortname))
        self.platform_path = os.path.join(self.src_path, self.platform)
        self.license_md_path = os.path.join(self.src_path, '..', 'LICENSE.md')
        self.license_txt_path = os.path.join(self.target_path, 'COPYING.txt')

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        pass

    def build(self):
        logger.info('Building %s for %s', self.name, self.platform)
        logger.info('Src path is %s', self.src_path)

        logger.info('Set up build dir')
        self._create_target_path()

        logger.info('Converting markdown files')
        self._convert_md_files()

        logger.info('Copy platform-specific files to build dir')
        self._copy_platform()

        logger.info('Copy common files to build dir')
        self._copy_common_dirs()

        logger.info('Set up results dir')
        self._create_results_dir()

        logger.info('Clean up build dir')
        self._clean_up(self.target_path, remove_blocklist=False)

    def _convert_md_files(self):
        mdtotextfile(self.license_md_path, self.license_txt_path)

    def _create_target_path(self):
        # create base build path if it doesn't already exist
        if not os.path.exists(self.target_path):
            logger.info(
                'Build dir does not exist, creating %s', self.target_path)
            os.makedirs(self.target_path)
        else:
            logger.info(
                'Build dir %s already exists, proceeding', self.target_path)

        # base build path exists
        assert os.path.isdir(self.target_path)

    def _copy_platform(self):
        # copy platform-specific content
        for f in os.listdir(self.platform_path):
            f_src = os.path.join(self.platform_path, f)

            # blocklist files and dirs by name
            # these files will not be copied
            if f in self._blocklist:
                logger.info('Skipping path (blocklisted) %s', f_src)
                continue

            f_dst = os.path.join(self.target_path, f)
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
            d_dst = os.path.join(self.target_path, d)
            copydir(d_src, d_dst)

    def _create_results_dir(self):
        # create result dir if it doesn't exist, otherwise don't touch it
        result_path = os.path.join(self.target_path, 'results')
        if not os.path.exists(result_path):
            logger.info('Result path does not exist, creating %s', result_path)
            os.makedirs(result_path)
        else:
            logger.info(
                'Result path %s already exists, proceeding', result_path)

    def _clean_up(self, path, remove_blocklist=True):
        logger.debug("Cleaning up %s", path)
        for f in os.listdir(path):
            fpath = os.path.join(path, f)
            if os.path.isdir(fpath):
                if f in self._blocklist:
                    logger.info('Removing %s dir from %s', f, path)
                    shutil.rmtree(fpath, ignore_errors=False, onerror=onerror)
                else:
                    self._clean_up(fpath, remove_blocklist=True)
