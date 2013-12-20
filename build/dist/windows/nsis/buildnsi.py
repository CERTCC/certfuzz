import sys
import os
import string
#import subprocess

# TODO remove if no longer needed
#def split_and_strip(line, delim=':'):
#    '''
#    Return the second half of the line after the delimiter, stripped of
#    whitespace
#    @param line:
#    @param delim: defaults to ":"
#    '''
#    return line.split(delim)[1].strip()


# TODO remove if no longer needed
#def get_svn_rev():
#    svninfo = subprocess.Popen(['svn', 'info'], stdout=subprocess.PIPE).communicate()[0]
#    svninfolines = svninfo.splitlines()
#    for line in svninfolines:
#        if line.startswith('Revision: '):
#            svn_revision = split_and_strip(line)
#
#    return svn_revision

def main(svn_rev=None, outfile=None, build_dir=None):

    distpath = ''

    if build_dir:
        distpath = '%s\BFF-windows-export' % build_dir
    else:
        distpath = 'BFF-windows-export'

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

#    svn_revision = get_svn_rev()
    svn_revision = svn_rev

    fp.write('!define VERSION "02.01.00.%s"\n' % svn_revision)
    fp.write('!define COPYRIGHT "CERT 2013"\n')
    fp.write('!define DESCRIPTION "FOE 2.1"\n')
    fp.write('!define LICENSE_TXT "%s\COPYING.txt"\n' % distpath)
    fp.write('!define INSTALLER_NAME "%s\..\..\FOE-2.1-r%s-setup.exe"\n' % (distpath, svn_revision))

    headerfile = open("nsis_header.txt", "r")
    headertext = headerfile.read()
    headerfile.close()

    fp.write(headertext)

    for path, dirs, files in os.walk(distpath):
        realpath = string.replace(path, distpath, "")
        fp.write('SetOutPath "$INSTDIR%s"\n' % realpath)
        for bfffile in files:
            filepath = os.path.join(os.path.abspath(path), bfffile)
            fp.write('File "%s"\n' % filepath)

    midfile = open("nsis_mid.txt", "r")
    midtext = midfile.read()
    midfile.close()

    fp.write(midtext)

    dirlist = []
    for path, dirs, files in os.walk(distpath):
        realpath = string.replace(path, distpath, "")
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
