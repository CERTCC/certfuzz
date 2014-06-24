'''
Created on Feb 6, 2014

@organization: cert.org
'''
import argparse
import logging
from distmods.build2 import builder_for
from distmods.build2 import SUPPORTED_PLATFORMS as builders
from distmods.errors import BuildError

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='enable debug messages', action="store_true")
    parser.add_argument('-v', '--verbose', help='enable debug messages', action="store_true")
    parser.add_argument('platform', type=str, help='One of {}'.format(builders.keys()))
    parser.add_argument('srcpath', type=str, help='path/to/bff/src')
    parser.add_argument('distpath', type=str, help='Directory to build into')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    if not args.platform in builders:
        print 'platform must be one of {}'.format(builders.keys())
        exit(1)

    # assume that we're running in a git checkout?
    try:
        builder = builder_for(args.platform)
    except BuildError as e:
        logger.error('Build Error: %s', e)
        return

    with builder(platform=args.platform,
               distpath=args.distpath,
               srcpath=args.srcpath) as b:
            b.build()

if __name__ == '__main__':
    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    main()
