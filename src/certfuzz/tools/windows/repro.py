'''
Created on Feb 4, 2013

@organization: cert.org
'''
import logging
import os
import re
import string
from subprocess import Popen

from certfuzz import debuggers
from certfuzz.debuggers import msec  # @UnusedImport
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools.filetools import mkdir_p, all_files, copy_file
from certfuzz.config.simple_loader import load_and_fix_config
from certfuzz.fuzztools.command_line_templating import get_command_args_list

logger = logging.getLogger()
logger.setLevel(logging.WARNING)


def parseiterpath(commandline):
    # Return the path to the iteration's fuzzed file
    for part in commandline.split():
        if 'bff-crash-' in part:
            return part


def getiterpath(msecfile):
    # Find the commandline in an msec file
    with open(msecfile) as mseclines:
        for line in mseclines:
            m = re.match('CommandLine: ', line)
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
                      dest='config',
                      help='path to the configuration file to use')
    parser.add_option('-w', '--windbg', dest='use_windbg',
                      action='store_true',
                      help='Use windbg instead of cdb')
    parser.add_option('-b', '--break', dest='break_on_start',
                      action='store_true',
                      help='Break on start of debugger session')
    parser.add_option('-d', '--debugheap', dest='debugheap',
                      action='store_true',
                      help='Use debug heap')
    parser.add_option('-p', '--debugger', dest='debugger',
                      help='Use specified debugger')
    parser.add_option('-f', '--filepath', dest='filepath',
                      action='store_true', help='Recreate original file path')
    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    cfg_file = options.config
    logger.debug('WindowsConfig file: %s', cfg_file)

    if len(args) and os.path.exists(args[0]):
        fullpath_fuzzed_file = os.path.abspath(args[0])
        fuzzed_file = BasicFile(fullpath_fuzzed_file)
        logger.info('Fuzzed file is: %s', fuzzed_file.path)
    else:
        parser.error('fuzzedfile must be specified')

    config = load_and_fix_config(cfg_file)

    iterationpath = ''
    if options.filepath:
        # Recreate same file path as fuzz iteration
        resultdir = os.path.dirname(fuzzed_file.path)
        for msecfile in all_files(resultdir, '*.msec'):
            print('** using msecfile: %s' % msecfile)
            iterationpath = getiterpath(msecfile)
            break

        if iterationpath:
            iterationdir = os.path.dirname(iterationpath)
            iterationfile = os.path.basename(iterationpath)
            mkdir_p(iterationdir)
            copy_file(fuzzed_file.path,
                      os.path.join(iterationdir, iterationfile))
            fuzzed_file.path = iterationpath

    cmd_as_args = get_command_args_list(
        config['target']['cmdline_template'], fuzzed_file.path)[1]

    args = []

    if options.use_windbg and options.debugger:
        parser.error('Options --windbg and --debugger are mutually exclusive.')

    if options.debugger:
        debugger_app = options.debugger
    elif options.use_windbg:
        debugger_app = 'windbg'
    else:
        debugger_app = 'cdb'

    args.append(debugger_app)

    if not options.debugger:
        # Using cdb or windbg
        args.append('-amsec.dll')
        if options.debugheap or config['debugger']['debugheap']:
            # do not use hd, xd options if debugheap is set
            pass
        else:
            args.extend(('-hd', '-xd', 'gp'))
        if not options.break_on_start:
            args.extend(('-xd', 'bpe', '-G'))
        args.extend(('-xd', 'wob', '-o',))
    args.extend(cmd_as_args)
    logger.info('args %s' % cmd_as_args)

    p = Popen(args, universal_newlines=True)
    p.wait()

if __name__ == '__main__':
    main()
