'''
Created on Jun 29, 2012

@organization: cert.org
'''
import logging
from .devmods.linux.linux_build import LinuxBuild
from .devmods.windows.windows_build import WindowsBuild
# from dev.osx import DarwinBuild

logger = logging.getLogger(__name__)

builders = {
            'linux': LinuxBuild,
            'windows': WindowsBuild,
#           'osx': DarwinBuild,
            }


def build(platform):
    try:
        builder = builders[platform]
    except KeyError:
        print('Platform must be one of %s' % list(builders.keys()))

    with builder() as b:
        b.build()


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    from optparse import OptionParser

    parser = OptionParser()
    options, args = parser.parse_args()

    if not len(args):
        allowed = list(builders.keys())
        allowed.append('all')
        print("Please specify one of %s" % allowed)
        exit()

    platform = args.pop(0)

    if platform == 'all':
        for p in list(builders.keys()):
            build(p)
    else:
        build(platform)
