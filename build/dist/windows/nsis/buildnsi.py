'''
Created on Feb 10, 2014

@organization: cert.org
'''
import sys
import os
import string


def main(version_string='', outfile=None, build_dir=None):

    distpath = 'BFF-windows-export'
    if build_dir:
        distpath = os.path.join(build_dir, distpath)

    # either open a file for writing, or just dump to stdout
    if outfile:
        fp = open(outfile, 'w')
    else:
        fp = sys.stdout

    os.chdir(os.path.dirname(__file__))

    topfile = open("nsis_top.txt", "r")
    toptext = topfile.read()
    topfile.close()

    fp.write(toptext)

    fp.write('!define VERSION "%s"\n' % version_string)
    fp.write('!define COPYRIGHT "CERT 2013"\n')
    fp.write('!define DESCRIPTION "BFF %s"\n' % version_string)
    fp.write('!define LICENSE_TXT "%s\..\COPYING.txt"\n' % distpath)
    fp.write('!define INSTALLER_NAME "%s\..\..\BFF-%s-setup.exe"\n' % (distpath, version_string))

    headerfile = open("nsis_header.txt", "r")
    headertext = headerfile.read()
    headerfile.close()

    # Write installer section
    fp.write(headertext)

    for path, dirs, files in os.walk(build_dir):
        realpath = string.replace(path, build_dir, "")
        fp.write('SetOutPath "$INSTDIR%s"\n' % realpath)
        for bfffile in files:
            filepath = os.path.join(os.path.abspath(path), bfffile)
            fp.write('File "%s"\n' % filepath)

    midfile = open("nsis_mid.txt", "r")
    midtext = midfile.read()
    midfile.close()

    # End of installer section

    # Write uninstaller section
    fp.write(midtext)

    dirlist = []
    for path, dirs, files in os.walk(build_dir):
        realpath = string.replace(path, build_dir, "")
        for bfffile in files:
            fp.write('Delete "$INSTDIR%s\%s"\n' % (realpath, bfffile))
            # Remove .pyc files as well.
            fileext = os.path.splitext(bfffile)[1][1:].strip()
            if fileext == "py":
                fp.write('Delete "$INSTDIR%s\%sc"\n' % (realpath, bfffile))

        dirlist.append(realpath)

    dirlist.reverse()
    for bffdir in dirlist:
        realdir = string.replace(bffdir, "..", "")
        fp.write('RmDir "$INSTDIR%s"\n' % realdir)

    footerfile = open("nsis_footer.txt", "r")
    footertext = footerfile.read()
    footerfile.close()

    fp.write(footertext)

    fp.close()

if __name__ == '__main__':
    main()
