'''
Created on Jan 31, 2011

@organization: cert.org

'''

import os
import fnmatch
import shutil
import tempfile
import logging
import sys

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

LICENSE_PREFIX = '### '
LICENSE_FILE = 'COPYING'

def parse_cmdline_args():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-d", "--debug", dest="debug", help="Turn on debugging output", action='store_true', default=False)
    parser.add_option("-v", "--verbose", dest="verbose", help="Set verbose mode", action='store_true', default=False)
    parser.add_option('', '--license', dest='license_file', help="Specify FILENAME containing license text", metavar='FILENAME', default=LICENSE_FILE)
    parser.add_option('', '--add', dest='add', help='If set, add license text to all .py files', action='store_true')
    parser.add_option('', '--remove', dest='remove', help='If set, remove license text from all .py files', action='store_true')
    parser.add_option('', '--replace', dest='replace', help='Equivalent to --remove --add', action='store_true')
    parser.add_option('', '--overwrite', dest='overwrite', help='Overwrite files (do not keep an .old version)', action='store_true')
    parser.add_option('', '--dir', dest='basedir', help='Path to base directory', metavar='DIR')
    parser.add_option('', '--prefix', dest='prefix', help='Prefix for license lines', metavar='STRING', default=LICENSE_PREFIX)
    options, dummy = parser.parse_args()

    if options.replace:
        options.remove = True
        options.add = True

    if not any([options.replace, options.add, options.remove]):
        print "One of --add, --remove, or --replace must be specified."
        parser.print_help()
        sys.exit(1)

    if not options.basedir:
        options.basedir = '.'

    return options

# Adapted from Python Cookbook 2nd Ed. p.88
def all_files(root, patterns='*', single_level=False, yield_folders=False):
    # Expand patterns from semicolon-separated string to list
    patterns = patterns.split(';')
    for path, subdirs, files in os.walk(root):
        if yield_folders:
            files.extend(subdirs)
        files.sort()
        for name in files:
            for pattern in patterns:
                if fnmatch.fnmatch(name, pattern):
                    filepath = os.path.join(path, name)
                    if os.path.isfile(filepath):
                        yield filepath
                    break
        if single_level:
            break

def write_to_screen(f, lines):
    print '*** WOULD BE WRITTEN TO %s ***' % f
    for l in lines:
        print l.rstrip()
    print '*** END OF FILE %s ***' % f

def write_to_file(f, lines, keep_old=True):
    # write the combined output to a tempfile
    (fp, fn) = tempfile.mkstemp(suffix='.py', text=True)
    content = ''.join(lines)
    os.write(fp, content)
    os.close(fp)

    # move the tempfile to the original
    if keep_old:
        shutil.move(f, '%s.old' % f)
    shutil.move(fn, f)

def build_license_lines(license_file, prefix=LICENSE_PREFIX):
    with open(license_file, 'r') as f:
        license_text = f.readlines()

    license_lines = []
    license_lines.append(LICENSE_PREFIX + 'BEGIN LICENSE ###\n')
    for l in license_text:
        license_lines.append(LICENSE_PREFIX + l.rstrip() + '\n')
    license_lines.append(LICENSE_PREFIX + 'END LICENSE ###\n')
    license_lines.append('\n')
    return license_lines

def find_extra_blank_lines(lines):
    f = lambda (x, y): not str(y).strip()
    blank_lines = filter(f, enumerate(lines))
    blank_line_indices = [x[0] for x in blank_lines]

    lines_safe_to_remove = []
    for i, val in enumerate(blank_line_indices):
        # skip the first one
        if i == 0:
            if val == 0:
                lines_safe_to_remove.append(val)
            continue

        if blank_line_indices[i - 1] == (val - 1):
            # this line is safe to remove as it's adjacent
            # to a blank line before it
            lines_safe_to_remove.append(val)

    return sorted(lines_safe_to_remove, reverse=True)

def remove_excess_blank_lines(lines):
    # remove extra blank lines
    for index in find_extra_blank_lines(lines):
        lines.pop(index)

    # remove any extra blank lines at beginning of file
    while lines and not lines[0].strip():
        lines.pop(0)

    # remove any extra blank lines at beginning of file
    while lines and not lines[-1].strip():
        lines.pop()

if __name__ == '__main__':
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    options = parse_cmdline_args()

    if options.add:
        license_file = options.license_file
        license_lines = build_license_lines(license_file, prefix=options.prefix)

    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)

    for f in all_files(options.basedir, '*.py'):

        orig_fp = open(f, 'r')
        file_lines = orig_fp.readlines()
        # skip lines that start with three hashes
        f_lines = [l for l in file_lines if not l.startswith(options.prefix)]
        orig_fp.close()

        # don't do anything with empty files
        if not len(f_lines):
            logger.info('Skipping empty file: %s', f)
            continue

        lines = []

        # check for shebang and keep it at the top if it exists
        skip_first_line = False
        if f_lines[0].startswith('#!'):
            logger.debug('Handling #! at beginning of %s', f)
            lines.append(f_lines[0])
            skip_first_line = True

        if options.remove:
            logger.debug('Removing license text')
        if options.add:
            logger.info('Adding license text to %s', f)
            # insert license lines
            lines.extend(license_lines)

        logger.debug('Appending the rest of the original file')
        # if we put a shebang at the top of the file, skip it here
        if skip_first_line:
            lines.extend(f_lines[1:])
        else:
            lines.extend(f_lines)

        remove_excess_blank_lines(lines)

        if options.debug:
            logger.debug('Output to screen only')
            write_to_screen(f, lines)
        else:
            orig_permissions = os.stat(f).st_mode & 0777
            keep_old = not options.overwrite
            write_to_file(f, lines, keep_old)
            os.chmod(f, orig_permissions)
