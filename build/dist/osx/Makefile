SHELL := /bin/bash

RM=rm -rfv
CP=cp -Rv
MV=mv -v
SVN=svn

LINUX_DIST_BASE=../linux
# base dir where we'll create the build
DIST_BASE=../../../dist_builds

PROJECT=BFF
PLATFORM=osx

BUILD_BASE=${INSTALLER_BASE}/bff

INSTALLER_BASE=installer
DMG_TEMPLATE=${INSTALLER_BASE}/BFF-template.dmg

SPARSE_DMG=${DIST_BASE}/BFF-sparse.sparseimage
FINAL_DMG=${DIST_BASE}/BFF.dmg

clean: clean_dmg clean_sparseimage
	${RM} ${BUILD_BASE}

linux_dist:
	# Build the linux trunk dist
	cd ${LINUX_DIST_BASE} && ${MAKE} trunk EXPORT_BASE=bff
	${MV} ${DIST_BASE}/bff ${INSTALLER_BASE}
	# get the svn revision from the repo
	
linux_tag_dist:
	# Build the linux dist
	# be sure to specify TAG
	cd ${LINUX_DIST_BASE} && ${MAKE} tag TAG=${TAG} EXPORT_BASE=bff
	${MV} ${DIST_BASE}/bff ${INSTALLER_BASE}
	# get the svn revision from the repo
	
linux_branch_dist:
	# Build the linux dist
	# be sure to specify BRANCH
	cd ${LINUX_DIST_BASE} && ${MAKE} branch BRANCH=${BRANCH} EXPORT_BASE=bff
	${MV} ${DIST_BASE}/bff ${INSTALLER_BASE}
	# get the svn revision from the repo

rename_files:
	${CP} ${BUILD_BASE}/README ${INSTALLER_BASE}/Readme.txt
	${CP} ${BUILD_BASE}/COPYING ${INSTALLER_BASE}/License.txt

osx_dist: clean linux_dist rename_files

osx_tag_dist: clean linux_tag_dist rename_files

osx_branch_dist: clean linux_branch_dist rename_files

unmount_old_dmg:
	ls -1d /Volumes/CERT\ BFF* | tr '\n' '\0' |  xargs -0 -n1 -Ixxx hdiutil detach "xxx"

${SPARSE_DMG}: clean_sparseimage convert_template mount_sparseimage package copy_pkg unmount_sparseimage

clean_sparseimage:
	${RM} ${SPARSE_DMG}
	
clean_sparseimage_again:
	${RM} ${SPARSE_DMG}

convert_template:
	hdiutil convert ${DMG_TEMPLATE} -format UDSP -o ${SPARSE_DMG}

mount_sparseimage: unmount_old_dmg
	hdiutil mount ${SPARSE_DMG}
	
package:
	cd ${INSTALLER_BASE} && /Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker \
	    -d BFF_installer.pmdoc -v -o "/Volumes/CERT BFF/Install CERT BFF.pkg"

copy_pkg:	
	cp -a ${INSTALLER_BASE}/build/pkgs/* /Volumes/CERT\ BFF/pkgs/

unmount_sparseimage:
	hdiutil detach "/Volumes/CERT BFF"

clean_dmg:
	${RM} ${FINAL_DMG}

${FINAL_DMG}: clean_dmg ${SPARSE_DMG}
	hdiutil convert ${SPARSE_DMG} -format UDBZ -o ${FINAL_DMG}

rename_dmg: ${FINAL_DMG}
	SVN_REV=`cd ${LINUX_DIST_BASE} && ${SVN} info | grep Revision | cut -d' ' -f2`; \
	VERSION=`cd ${BUILD_BASE} && grep __version__ bff.py | cut -d'=' -f2 | sed -e "s/ //g" -e "s/\'//g"`; \
	${MV} ${FINAL_DMG} ${DIST_BASE}/BFF-$$VERSION-$$SVN_REV.dmg

dist: osx_dist ${SPARSE_DMG} ${FINAL_DMG} clean_sparseimage_again rename_dmg

tag_dist: osx_tag_dist ${SPARSE_DMG} ${FINAL_DMG} clean_sparseimage_again rename_dmg

branch_dist: osx_branch_dist ${SPARSE_DMG} ${FINAL_DMG} clean_sparseimage_again rename_dmg
