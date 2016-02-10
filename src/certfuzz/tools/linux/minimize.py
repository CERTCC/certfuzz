'''
Created on Apr 9, 2012

@organization: cert.org
'''
import logging
import os
import sys

from certfuzz import debuggers
from certfuzz.testcase.testcase_linux import LinuxTestcase
from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools import filetools, text
from certfuzz.minimizer.unix_minimizer import UnixMinimizer as Minimizer
from certfuzz.config.simple_loader import load_and_fix_config


mydir = os.path.dirname(os.path.abspath(__file__))
parentdir = os.path.abspath(os.path.join(mydir, '..'))
sys.path.append(parentdir)


logger = logging.getLogger()


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
    parser.add_option('-t', '--target', dest='target',
                      help='the file to minimize to (typically the seedfile)')
    parser.add_option('-o', '--outdir', dest='outdir',
                      help='dir to write output to')
    parser.add_option('-s', '--stringmode', dest='stringmode', action='store_true',
                      help='minimize to a string rather than to a target file')
    parser.add_option('-x', '--preferx', dest='prefer_x_target',
                      action='store_true',
                      help='Minimize to \'x\' characters instead of Metasploit string pattern')
    parser.add_option('-f', '--faddr', dest='keep_uniq_faddr',
                      action='store_true',
                      help='Use exception faulting addresses as part of crash signature')
    parser.add_option('-b', '--bitwise', dest='bitwise', action='store_true',
                      help='if set, use bitwise hamming distance. Default is bytewise')
    parser.add_option('-c', '--confidence', dest='confidence',
                      help='The desired confidence level (default: 0.999)',
                      type='float')
    parser.add_option('-g', '--target-size-guess', dest='initial_target_size',
                      help='A guess at the minimal value (int)', type='int')
    parser.add_option('', '--config', dest='config',
                      help='path to the configuration file to use')
    parser.add_option('', '--timeout', dest='timeout',
                      metavar='N', type='int', default=0,
                      help='Stop minimizing after N seconds (default is 0, never time out).')

    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)

    if options.config:
        cfg_file = os.path.expanduser(options.config)
    else:
        if os.path.isfile("../conf.d/bff.yaml"):
            cfg_file = "../conf.d/bff.cfg"
        elif os.path.isfile("conf.d/bff.yaml"):
            cfg_file = "conf.d/bff.yaml"
        else:
            parser.error('Configuration file (--config) option must be specified.')
    logger.debug('Config file: %s', cfg_file)

    if options.stringmode and options.target:
        parser.error('Options --stringmode and --target are mutually exclusive.')

    # Set some default options. Fast and loose if in string mode
    # More precise with minimize to seedfile
    if not options.confidence:
        if options.stringmode:
            options.confidence = 0.5
        else:
            options.confidence = 0.999
    if not options.initial_target_size:
        if options.stringmode:
            options.initial_target_size = 100
        else:
            options.initial_target_size = 1

    if options.confidence:
        try:
            options.confidence = float(options.confidence)
        except:
            parser.error('Confidence must be a float.')
    if not 0.0 < options.confidence < 1.0:
        parser.error('Confidence must be in the range 0.0 < c < 1.0')

    confidence = options.confidence

    if options.outdir:
        outdir = options.outdir
    else:
        outdir = "./minimizer_out"

    if not os.path.exists(outdir):
        filetools.make_directories(outdir)

    if not os.path.isdir(outdir):
        parser.error('--outdir must either already be a dir or not exist: %s' % outdir)

    if len(args) and os.path.exists(args[0]):
        fuzzed_file = BasicFile(args[0])
        logger.info('Fuzzed file is %s', fuzzed_file)
    else:
        parser.error('fuzzedfile must be specified')


    if options.target:
        seedfile = BasicFile(options.target)
    else:
        seedfile = None

    min2seed = not options.stringmode
    filename_modifier = ''

    crashers_dir = '.'

    cfg = load_and_fix_config(cfg_file)

    with LinuxTestcase(cfg=cfg,
                       seedfile=seedfile,
                       fuzzedfile=fuzzed_file,
                       program=cfg['target']['program'],
                       debugger_timeout=cfg['debugger']['runtimeout'],
                       killprocname=cfg['target']['killprocname'],
                       backtrace_lines=cfg['debugger']['backtracelevels'],
                       crashers_dir=crashers_dir,
                       workdir_base=None,
                       keep_faddr=options.keep_uniq_faddr) as crash:

        filetools.make_directories(crash.tempdir)
        logger.info('Copying %s to %s', fuzzed_file.path, crash.tempdir)
        filetools.copy_file(fuzzed_file.path, crash.tempdir)

        with Minimizer(cfg=cfg, crash=crash, crash_dst_dir=outdir,
                                 seedfile_as_target=min2seed,
                                 bitwise=options.bitwise,
                                 confidence=confidence,
                                 logfile='./min_log.txt',
                                 tempdir=crash.tempdir,
                                 maxtime=options.timeout,
                                 preferx=options.prefer_x_target,
                                 keep_uniq_faddr=options.keep_uniq_faddr) as minimize:
            minimize.save_others = False
            minimize.target_size_guess = int(options.initial_target_size)
            minimize.go()

            if options.stringmode:
                logger.debug('x character substitution')
                length = len(minimize.fuzzed_content)
                if options.prefer_x_target:
                    # We minimized to 'x', so we attempt to get metasploit as a freebie
                    targetstring = list(text.metasploit_pattern_orig(length))
                    filename_modifier = '-mtsp'
                else:
                    # We minimized to metasploit, so we attempt to get 'x' as a freebie
                    targetstring = list('x' * length)
                    filename_modifier = '-x'

                fuzzed = list(minimize.fuzzed_content)
                for idx in minimize.bytemap:
                    logger.debug('Swapping index %d', idx)
                    targetstring[idx] = fuzzed[idx]
                filename = ''.join((crash.fuzzedfile.root, filename_modifier, crash.fuzzedfile.ext))
                metasploit_file = os.path.join(crash.tempdir, filename)

                with open(metasploit_file, 'wb') as f:
                    f.writelines(targetstring)

        crash.copy_files(outdir)
        crash.clean_tmpdir()

if __name__ == '__main__':
    main()
