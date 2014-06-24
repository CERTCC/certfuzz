#!/bin/bash
revision=`svn info | grep Revision | cut -d' ' -f2`
pushd ../../linux
make clean svn_export cleanup
VERSION=`grep __version__ bff.py | cut -d'=' -f2 | sed -e "s/ //g" -e "s/\'//g"`
popd
rm -rf bff
mkdir bff
cp -a ../../linux/dist/* bff
cp bff/README Readme.txt
cp bff/COPYING License.txt
ls -1d /Volumes/CERT\ BFF* | tr '\n' '\0' |  xargs -0 -n1 -Ixxx hdiutil detach "xxx"
hdiutil convert BFF-template.dmg -format UDSP -o BFF-sparse.sparseimage
hdiutil mount BFF-sparse.sparseimage
/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker -d BFF_installer.pmdoc -v -o "/Volumes/CERT BFF/Install CERT BFF.pkg"
cp -a build/pkgs/* /Volumes/CERT\ BFF/pkgs/
hdiutil detach "/Volumes/CERT BFF"
rm BFF.dmg
hdiutil convert BFF-sparse.sparseimage -format UDBZ -o BFF.dmg
rm BFF-sparse.sparseimage
mv BFF.dmg ../../../dev_builds/BFF-$VERSION-$revision.dmg
