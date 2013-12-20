'''
Created on Dec 9, 2013

@author: adh
'''
import string
import subprocess
import os
import shutil

from ..build_base import Build
from ..svn import svn_rev
from ..errors import BuildError


class LinuxBuild(Build):
    PLATFORM = 'linux'
    LICENSE_FILE = 'COPYING'

    def package(self):
        '''
        Creates a zip file containing the code
        '''
        if self.zipfile:
            zipfile_base = self.zipfile
        elif self.zipfile_template:
            rev = svn_rev(self.svn_url)
            zipfile_template = string.Template(self.zipfile_template)
            zipfile_base = zipfile_template.substitute(SVN_REV=rev)
        else:
            raise BuildError('Unable to determine zipfile name')

        export_dir = os.path.join(self.build_dir, self.export_base)
        parent_zipfile = os.path.join('..', zipfile_base)
        args = ['zip', '-r', '-v', parent_zipfile, '.']
        subprocess.call(args, cwd=export_dir)

        source = os.path.join(self.build_dir, zipfile_base)
        target = os.path.join(self.DIST_BASE, zipfile_base)
        if os.path.exists(target):
            os.remove(target)
        shutil.move(source, target)
