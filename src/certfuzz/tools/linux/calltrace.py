'''
Created on April 28, 2013

@organization: cert.org
'''
import logging
import os
import re
import platform
from subprocess import Popen
from certfuzz.config.simple_loader import load_and_fix_config
from certfuzz.fuzztools.command_line_templating import get_command_args_list

try:
    from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
    from certfuzz.file_handlers.basicfile import BasicFile
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    import sys
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
    from certfuzz.file_handlers.basicfile import BasicFile

logger = logging.getLogger()
logger.setLevel(logging.WARNING)


def parseiterpath(commandline):
    # Return the path to the iteration's fuzzed file
    for part in commandline.split():
        if 'campaign_' in part and 'iteration_' in part:
            # This is the part of the commandline that looks like it's
            # the fuzzed file
            return part


def getiterpath(gdbfile):
    # Find the commandline in an msec file
    with open(gdbfile) as gdblines:
        for line in gdblines:
            m = re.match('Running: ', line)
            if m:
                return parseiterpath(line)


def main():
    from optparse import OptionParser

    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    usage = "usage: %prog [options] fuzzedfile"
    parser = OptionParser(usage)
    parser.add_option('', '--debug', dest='debug', action='store_true',
                      help='Enable debug messages (overrides --verbose)')
    parser.add_option('', '--verbose', dest='verbose', action='store_true',
                      help='Enable verbose messages')
    parser.add_option('-c', '--config', default='configs/bff.yaml',
                      dest='config', help='path to the configuration file to use')
    parser.add_option('-a', '--args', dest='print_args',
                      action='store_true',
                      help='Print function arguments')
    parser.add_option('-o', '--out', dest='outfile',
                      help='PIN output file')
    parser.add_option('-f', '--filepath', dest='filepath',
                      action='store_true', help='Recreate original file path')

    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if options.outfile:
        outfile = options.outfile
    else:
        outfile = 'calltrace.log'

    cfg_file = options.config
    logger.debug('Config file: %s', cfg_file)

    if len(args) and os.path.exists(args[0]):
        fullpath_fuzzed_file = os.path.abspath(args[0])
        fuzzed_file = BasicFile(fullpath_fuzzed_file)
        logger.info('Fuzzed file is: %s', fuzzed_file.path)
    else:
        parser.error('fuzzedfile must be specified')

    iterationpath = ''

    if options.filepath:
        # Recreate same file path as fuzz iteration
        resultdir = os.path.dirname(fuzzed_file.path)
        for gdbfile in all_files(resultdir, '*.gdb'):
            print('** using gdb: %s' % gdbfile)
            iterationpath = getiterpath(gdbfile)
            break
        if iterationpath:
            iterationdir = os.path.dirname(iterationpath)
            iterationfile = os.path.basename(iterationpath)
            if iterationdir:
                mkdir_p(iterationdir)
                copy_file(fuzzed_file.path,
                          os.path.join(iterationdir, iterationfile))
                fullpath_fuzzed_file = iterationpath

    config = load_and_fix_config(cfg_file)

    cmd_as_args = get_command_args_list(
        config['target']['cmdline_template'], fullpath_fuzzed_file)[1]
    args = []

    pin = os.path.expanduser('~/pin/pin')
    pintool = os.path.expanduser('~/pintool/calltrace.so')
    args = [pin, '-injection', 'child', '-t',
            pintool, '-o', outfile]
    if options.print_args:
        args.append('-a')
    args.append('--')
    args.extend(cmd_as_args)

    logger.info('args %s' % args)

    p = Popen(args, universal_newlines=True)
    p.wait()


if __name__ == '__main__':
    main()
