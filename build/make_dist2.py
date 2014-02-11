'''
Created on Feb 6, 2014

@organization: cert.org
'''
import argparse
import logging
from dist.build2 import Build
from dist.build2 import SUPPORTED_PLATFORMS as builders

logger = logging.getLogger(__name__)


def main():
    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

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
    with Build(platform=args.platform,
               distpath=args.distpath,
               srcpath=args.srcpath) as b:
        b.build()

if __name__ == '__main__':
    main()
