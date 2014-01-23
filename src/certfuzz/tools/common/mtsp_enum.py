'''
Created on Mar 8, 2013

@organization: cert.org
'''
import logging
import argparse
import os.path

try:
    from certfuzz.fuzztools.text import enumerate_string
except ImportError:
    # if we got here, we probably don't have .. in our PYTHONPATH
    import sys
    mydir = os.path.dirname(os.path.abspath(__file__))
    parentdir = os.path.abspath(os.path.join(mydir, '..'))
    sys.path.append(parentdir)
    from certfuzz.fuzztools.text import enumerate_string


def main():
    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--debug', help='', action='store_true')
    group.add_argument('-v', '--verbose', help='', action='store_true')
    parser.add_argument('searchstring',
                        type=str,
                        help='The string to enumerate')
    parser.add_argument('fuzzedfile',
                        help='Path to a fuzzedfile',
                        type=str)

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    enumerate_string(path=args.fuzzedfile, str_to_enum=args.searchstring)

if __name__ == '__main__':
    main()
