'''
Created on Dec 9, 2013

@author: adh
'''
import os
import shutil
import logging
import subprocess

from ..build_base2 import Build

logger = logging.getLogger(__name__)

basedir = os.path.dirname(__file__)


class WindowsBuild(Build):
    PLATFORM = 'windows'
    LICENSE_FILE = 'COPYING.txt'

    def package(self):
        '''
        Builds a Windows Installer
        '''
        logger.debug('Import buildnsi')
        from .nsis import buildnsi

        nsidir = os.path.join(self.build_dir, '..')
        # Copy files required by nsis
        for f in ['cert.ico', 'EnvVarUpdate.nsh', 'vmwarning.txt']:
            src = os.path.join(basedir, 'nsis', f)
            logger.debug('Copy %s -> %s', src, nsidir)
            shutil.copy(src, nsidir)

        nsifile = os.path.join(nsidir, 'bff.nsi')
        logger.debug('nsi file is %s', nsifile)

        version_string = "2.8.0.%s" % self.git_rev
        git_hash = self.git_hash
        # generate the nsi file
        buildnsi.main(version_string=version_string, git_hash=git_hash, outfile=nsifile, build_dir=self.build_dir)

        # invoke makensis on the file we just made
        logger.debug('invoking makensis on %s', nsifile)
        subprocess.call(['makensis', nsifile])

        distpath = 'BFF-windows-export'
        if self.build_dir:
            distpath = os.path.join(self.build_dir, distpath)

        exename = 'BFF-%s-%s-setup.exe' % (version_string, git_hash)
        exefile = '%s\..\..\%s' % (distpath, exename)
        self.target = os.path.join(os.path.dirname(self.target), exename)
        self._move_to_target(exefile)
