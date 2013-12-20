import sys
import os
import string
import subprocess

def split_and_strip(line, delim=':'):
    '''
    Return the second half of the line after the delimiter, stripped of
    whitespace
    @param line:
    @param delim: defaults to ":"
    '''
    return line.split(delim)[1].strip()


def get_svn_revision():
    svninfo = subprocess.Popen(['svn', 'info'], stdout=subprocess.PIPE).communicate()[0]
    for line in svninfo.splitlines():
        if line.startswith('Revision: '):
            return split_and_strip(line)

def print_file(f):
    with open(f, 'r') as fp:
        print fp.read()

class NsiFile(object):
    def __init__(self):
        self.top = 'nsis_top.txt'
        self.header = 'nsis_header.txt'
        self.mid = 'nsis_mid.txt'
        self.footer = 'nsis_footer.txt'

    def __enter__(self):
        self._buildlines()
        return self

    def __exit__(self, etype, value, traceback):
        return

    def _readlines(self, infile):
        with open(infile, 'r') as fp:
            return [l.rstrip() for l in fp.readlines()]

    def print_file(self, outfile):
        # add newlines to lines that need it
        for i, l in enumerate(self.lines):
            if not l.endswith('\n'):
                self.lines[i] = l + '\n'

        with open(outfile, 'w') as fp:
            fp.writelines(self.lines)

    def _get_files_to_copy(self):
        lines = []
        distpath = os.path.join('..', 'dist')
        for path, dirs, files in os.walk(distpath):
            # realpath is the path relative to distpath
            realpath = os.path.relpath(path, distpath)
            outpath = os.path.join('$INSTDIR', realpath)
            lines.append('SetOutPath "%s"' % outpath)
            for f in files:
                filepath = os.path.join(os.path.abspath(path), f)
                lines.append('File "%s"' % filepath)
        return lines

    def _get_version(self):
        return '!define VERSION "02.00.%s.00"' % get_svn_revision()

    def _get_files_to_delete(self):
        distpath = os.path.join('..', 'dist')
        dirlist = []
        lines = []
        for path, dirs, files in os.walk(distpath):
            # realpath is the path relative to distpath
            realpath = os.path.relpath(path, distpath)
            dirlist.append(realpath)
            for f in files:
                delpath = os.path.normpath(os.path.join('$INSTDIR', realpath, f))
                lines.append('Delete "%s"' % delpath)
                # Remove .pyc files as well.
                fileext = os.path.splitext(f)[1][1:].strip()
                if fileext == "py":
                    delpath = os.path.normpath(os.path.join('$INSTDIR', realpath, f + 'c'))
                    lines.append('Delete "%s"' % delpath)

        dirlist.reverse()
        for d in dirlist:
            if d == '.':
                continue

            realdir = d.replace("..", "")
            rmpath = os.path.normpath(os.path.join('$INSTDIR', realdir))
            lines.append('RmDir "%s"' % rmpath)

        return lines

    def _buildlines(self):
        self.lines = []
        self.lines.extend(self._readlines(self.top))
        self.lines.append(self._get_version())
        self.lines.extend(self._readlines(self.header))
        self.lines.extend(self._get_files_to_copy())
        self.lines.extend(self._readlines(self.mid))
        self.lines.extend(self._get_files_to_delete())
        self.lines.extend(self._readlines(self.footer))

def main():
    os.chdir(sys.path[0])

    with NsiFile() as nsi:
        for l in nsi.lines:
            print l

if __name__ == '__main__':
    main()
