'''
Created on Dec 9, 2013

@author: adh
'''
import os
import shutil

import subprocess

from ..build_base import Build
from ..errors import BuildError

basedir = os.path.dirname(__file__)


class WindowsBuild(Build):
    PLATFORM = 'windows'
    LICENSE_FILE = 'COPYING.txt'

    def prune(self):
        super(self.__class__, self).prune()

        # prune everything in certfuzz/analysis except drillresults
        cfadir = os.path.join(self.export_path, 'certfuzz', 'analysis')
        p_to_del = []
        if os.path.exists(cfadir):
            p_to_del.extend([os.path.join(cfadir, x) for x in os.listdir(cfadir) if x != "drillresults"])

        # prune these dirs too
        for x in ['certfuzz/analyzers',
                  'certfuzz/campaign/config/bff_config.py',
                  'certfuzz/debuggers/crashwrangler.py',
                  'certfuzz/debuggers/gdb.py',
                  'certfuzz/debuggers/mr_crash_hash.py',
                  'certfuzz/debuggers/nulldebugger.py',
                  'certfuzz/debuggers/templates',
                  'build',
                  'installer',
                  'test',
                  ]:
            p_to_del.append(os.path.join(self.export_path, x))

        for p in p_to_del:
            if os.path.isfile(p):
                os.remove(p)
            elif os.path.isdir(p):
                shutil.rmtree(p)

            if os.path.exists(p):
                raise BuildError("Unable to remove %s" % p)

    def package(self):
        '''
        Builds a Windows Installer
        '''
        from .nsis import buildnsi

        # Copy files required by nsis
        for f in ['cert.ico', 'EnvVarUpdate.nsh', 'vmwarning.txt']:
            src = os.path.join(basedir, 'nsis', f)
            shutil.copy(src, self.build_dir)
#        shutil.copy('dist/windows/nsis/cert.ico', self.build_dir)
#        shutil.copy('dist/windows/nsis/EnvVarUpdate.nsh', self.build_dir)

        nsifile = os.path.join(self.build_dir, 'foe2.nsi')

        # generate the nsi file
        buildnsi.main(svn_rev=self.svn_rev, outfile=nsifile, build_dir=self.build_dir)
#        subprocess.call(args, stdout=open(nsifile, 'w'))

        # invoke makensis on the file we just made
        subprocess.call(['makensis', nsifile])
