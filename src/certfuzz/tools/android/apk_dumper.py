'''
Created on Feb 28, 2013

@organization: cert.org
'''
import logging
import argparse
from certfuzz.android.api.aapt import Aapt
from certfuzz.android.api.android_manifest import AndroidManifest
import os


def main():
    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--debug', help='', action='store_true')
    group.add_argument('-v', '--verbose', help='', action='store_true')
    parser.add_argument('apk',
                        help='Path to an apk',
                        type=str)

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    aapt = Aapt()
    aapt.get_manifest(os.path.expanduser(args.apk))
    manifest_text = aapt.stdout

    manifest = AndroidManifest(manifest_text)

    vstr = '{} {}'.format(os.path.basename(args.apk), manifest.version_info)
    print '#' * (len(vstr) + 4)
    print '# {} #'.format(vstr)
    print '#' * (len(vstr) + 4)
    print
    for mimetype in manifest.mimetypes:
        print mimetype
    print

if __name__ == '__main__':
    main()
