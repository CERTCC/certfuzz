#!/usr/bin/env python
'''
Created on Jun 29, 2012

@organization: cert.org
'''
from optparse import OptionParser

from dist.linux.linux_build import LinuxBuild
from dist.osx.darwin_build import DarwinBuild
from dist.windows.windows_build import WindowsBuild
from dist.errors import BuildError

import subprocess
import logging

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.WARNING)

build_class = {
           'linux': LinuxBuild,
           'windows': WindowsBuild,
           'osx': DarwinBuild,
           }

commands = ['branch', 'tag', 'trunk']
cmd_args = {
            'branch': '<branch_name>',
            'tag': '<tag_name>'
            }


def usage():
    print 'usage: $0 <platform> <command> <args>'
    print 'where'
    print '<platform> is one of: %s' % build_class.keys()
    print '<command> is one of: tag, branch, trunk'
    print 'tag args: tag-name'
    exit()


def fail(msg):
    print 'Build failed: %s' % msg
    exit(1)


def ls_dist_base():
    print
    print
    print
    print
    header = "*** Listing build dir %s ***" % builder.DIST_BASE
    print "*" * len(header)
    print header
    print "*" * len(header)
    print
    subprocess.call(['ls', '-l', builder.DIST_BASE])

if __name__ == '__main__':
    usage = 'usage: %prog <platform> <command> <command_args>'
    desc_parts = ['platforms: %s' % build_class.keys(),
                  'commands: %s' % commands,
                  'command_args: %s' % ['%s: %s' % (k, v) for (k, v) in cmd_args.iteritems()]
                  ]
    description = '\n'.join(desc_parts)

    parser = OptionParser(usage=usage, description=description)
    parser.add_option('', '--verbose', dest='verbose', action='store_true', default=False, help='Enable verbose logging')
    parser.add_option('', '--debug', dest='debug', action='store_true', default=False, help='Enable debug logging (overrides --verbose)')
    parser.add_option('', '--url', dest='url', default=None, help='Enable verbose logging')

    (options, args) = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)

    if options.url is None:
        fail('Specify svn repo location using --url option')

    if not len(args):
        parser.print_usage()
        exit()

    _url = options.url

    platform = args.pop(0)

    try:
        builder = build_class[platform]
    except KeyError:
        fail('Platform must be one of %s' % build_class.keys())

    buildtype = args.pop(0)

    if not buildtype in commands:
        fail('Command must be one of %s' % commands)

    logfile_hdlr = logging.FileHandler('make_dist_%s_%s.log' % (platform, buildtype), mode='w')
    logger.addHandler(logfile_hdlr)

    try:
        with builder(buildtype, args, url=_url) as build:
            build.build()
    except BuildError, e:
        fail(e)

    ls_dist_base()
