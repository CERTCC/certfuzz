'''
Created on Dec 9, 2013

@author: adh
'''
import os
import shutil
import subprocess
#import string
import re

import logging

from ..build_base import Build
from ..svn import svn_rev
from ..errors import BuildError

from string import Template

logger = logging.getLogger(__name__)


# mac-specific
def hdiutil(command, *parameters):
    args = ['hdiutil', command]
    args.extend(parameters)
    logger.debug(args)
    subprocess.call(args)


# mac-specific
def packagemaker(working_dir='.', *parameters):
    args = ['/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker']
    args.extend(parameters)
    # pushd
    oldcwd = os.getcwd()
    os.chdir(working_dir)

    logger.debug('cd %s && %s', working_dir, args)
    subprocess.call(args)

    # popd
    os.chdir(oldcwd)


class DarwinBuild(Build):
    # this platform string is used to decide which code dir to export from svn
    # OSX and linux use the same code.
    PLATFORM = 'linux'
    LICENSE_FILE = 'COPYING'
    INSTALLER_BASE = os.path.join(Build.BUILD_BASE, 'osx', 'installer')
    SHARED_DEPS = '/Volumes/xcat/build/bff/osx/'
    LOCAL_DEPS = os.path.expanduser('~/bff_deps/')
    dmg_file = ''

    def __init__(self, *args, **kwargs):
        Build.__init__(self, *args, **kwargs)

        self.dmg_template = None
        self.sparse_image = None
        self.final_dmg = None
        self.dmg_file_template = None

    def __exit__(self, etype, value, traceback):
        Build.__exit__(self, etype, value, traceback)

        # only clean up if we are exiting normally
        if not etype:
            try:
                os.remove(self.sparse_image)
            except:
                print "Failed to remove %s" % self.sparse_image

    def process_args(self):
        '''
        Process the other arguments passed to the build object
        '''
        super(self.__class__, self).process_args()

        if self.buildtype == 'tag':
            self.dmg_file = '%s-%s.dmg' % (self.PROJECT, self.tag)
        elif self.buildtype == 'branch':
            self.dmg_file_template = '%s-%s-r$SVN_REV.dmg' % (self.PROJECT, self.branch)
        elif self.buildtype == 'trunk':
            self.dmg_file_template = '%s-trunk-r$SVN_REV.dmg' % (self.PROJECT)
        else:
            raise BuildError('Unknown buildtype: %s' % self.buildtype)

#    def export(self):
#        # export the linux code
#        super(self.__class__, self).export()

    def refine(self):
        Build.refine(self)

        # pushd
        oldcwd = os.getcwd()
        os.chdir(self.export_path)

        # now move the whole export over to installer
        target = os.path.join(self.INSTALLER_BASE, 'bff')
        if os.path.exists(target):
            logger.debug('Deleting old target %s', target)
            shutil.rmtree(target)
        logger.debug('Copying %s -> %s', self.export_path, target)
        shutil.copytree(self.export_path, target)

        # Copy Readme and License files to installer directory
        logger.debug('Copying Readme and License files...')
        os.chdir(target)
        shutil.copy('README', '../Readme.txt')
        shutil.copy('COPYING', '../License.txt')

    def _build_sparseimage(self):
        #${SPARSE_DMG}: clean_sparseimage convert_template mount_sparseimage package copy_pkg unmount_sparseimage

        #DMG_TEMPLATE=${INSTALLER_BASE}/BFF-template.dmg
        self.dmg_template = os.path.join(self.INSTALLER_BASE, 'BFF-template.dmg')

        #SPARSE_DMG=${DIST_BASE}/BFF-sparse.sparseimage
        self.sparse_image = os.path.join(self.DIST_BASE, 'BFF-sparse.sparseimage')

        #clean_sparseimage:
        if os.path.exists(self.sparse_image):
            #    ${RM} ${SPARSE_DMG}
            logger.debug('Deleting old sparseimage', self.sparse_image)
            os.remove(self.sparse_image)

        #convert_template:
        #    hdiutil convert ${DMG_TEMPLATE} -format UDSP -o ${SPARSE_DMG}
        hdiutil('convert', self.dmg_template, '-format', 'UDSP', '-o', self.sparse_image)

        #unmount_old_dmg:
        #    ls -1d /Volumes/CERT\ BFF* | tr '\n' '\0' |  xargs -0 -n1 -Ixxx hdiutil detach "xxx"
        for d in os.listdir('/Volumes'):
            if d.startswith('CERT BFF'):
                volume_to_detach = os.path.join('/Volumes', d)
                hdiutil('detach', volume_to_detach)

        #mount_sparseimage: unmount_old_dmg
        #    hdiutil mount ${SPARSE_DMG}
        hdiutil('mount', self.sparse_image)

        #package:
        #    cd ${INSTALLER_BASE} && /Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker \
        #        -d BFF_installer.pmdoc -v -o "/Volumes/CERT BFF/Install CERT BFF.pkg"
        packagemaker(self.INSTALLER_BASE,
                     '-d', 'BFF_installer.pmdoc',
                     '-v',
                     '-o', '/Volumes/CERT BFF/Install CERT BFF.pkg'
                     )

        #copy_pkg:
        #    cp -a ${INSTALLER_BASE}/build/pkgs/* /Volumes/CERT\ BFF/pkgs/
        srcdir = os.path.join(self.INSTALLER_BASE, 'build', 'pkgs')
        dstdir = '/Volumes/CERT BFF/pkgs'

        # TODO: replace this with a native api call
        # note however that shutil.copytree() is not sufficient
        # because it requires that the target dir not already exist
        logger.debug('Copy %s -> %s', srcdir, dstdir)
        subprocess.call('cp -a %s %s' % (os.path.join(srcdir, '*'), re.escape(dstdir)), shell=True)

        #unmount_sparseimage:
        #    hdiutil detach "/Volumes/CERT BFF"
        hdiutil('detach', '/Volumes/CERT BFF')

    def _convert_sparseimage_to_dmg(self):
        #FINAL_DMG=${DIST_BASE}/BFF.dmg
        self.final_dmg = os.path.join(self.DIST_BASE, 'BFF.dmg')

        #clean_dmg:
        #    ${RM} ${FINAL_DMG}
        if os.path.exists(self.final_dmg):
            logger.debug('Deleting old dmg %s', self.final_dmg)
            os.remove(self.final_dmg)

        #${FINAL_DMG}: clean_dmg ${SPARSE_DMG}
        #    hdiutil convert ${SPARSE_DMG} -format UDBZ -o ${FINAL_DMG}

        hdiutil('convert', self.sparse_image, '-format', 'UDBZ', '-o', self.final_dmg)

        #rename_dmg: ${FINAL_DMG}
        #    SVN_REV=`cd ${LINUX_DIST_BASE} && ${SVN} info | grep Revision | cut -d' ' -f2`; \
        #    VERSION=`cd ${BUILD_BASE} && grep __version__ bff.py | cut -d'=' -f2 | sed -e "s/ //g" -e "s/\'//g"`; \
        if self.dmg_file:
            dmg_file_base = self.dmg_file
        elif self.dmg_file_template:
            rev = svn_rev(self.svn_url)
            dmg_file_template = Template(self.dmg_file_template)
            dmg_file_base = dmg_file_template.substitute(SVN_REV=rev)
        else:
            raise BuildError('Unable to determine dmg file name')

        #    ${MV} ${FINAL_DMG} ${DIST_BASE}/BFF-$$VERSION-$$SVN_REV.dmg
        dmg_file = os.path.join(self.DIST_BASE, dmg_file_base)
        logger.debug('Move %s -> %s', self.final_dmg, dmg_file)
        os.rename(self.final_dmg, dmg_file)

    def _sync_dependencies(self):
        # Retrieve binary dependecies for building OSX installer
        # rsync -EaxSv /Volumes/xcat/build/bff/osx/ installer/
        # TODO: What if rsync fails?
        subprocess.call(['rsync', '-EaxSv', self.SHARED_DEPS, self.LOCAL_DEPS])
        subprocess.call(['rsync', '-EaxSv', self.LOCAL_DEPS, self.INSTALLER_BASE])

    def package(self):
        self._sync_dependencies()
        self._build_sparseimage()
        self._convert_sparseimage_to_dmg()
