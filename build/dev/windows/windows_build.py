'''
Created on Dec 9, 2013

@author: adh
'''
from .. import Build
import os
import sys
mydir = os.path.dirname(os.path.abspath(__file__))
parentdir = os.path.abspath(os.path.join(mydir, '..'))
sys.path.append(parentdir)
from dev.misc import copyfile


class WindowsBuild(Build):
    _name = 'BFF'
    _platform = 'windows'

    def _copy_platform(self):
        target_path = self.target_path
        Build._copy_platform(self)
        # Copy example bff.yaml file to configs directory
        f_src = os.path.join(target_path, 'configs', 'examples', 'bff.yaml')
        f_dst = os.path.join(target_path, 'configs')
        copyfile(f_src, f_dst)
