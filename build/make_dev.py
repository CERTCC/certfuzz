'''
Created on Jun 29, 2012

@organization: cert.org
'''

from dev.linux.linux_build import LinuxBuild
from dev.windows.windows_build import WindowsBuild
#from dev.osx import DarwinBuild

builders = {
            'linux': LinuxBuild,
            'windows': WindowsBuild,
#           'osx': DarwinBuild,
            }


def build(platform):
    try:
        builder = builders[platform]
    except KeyError:
        print 'Platform must be one of %s' % builders.keys()

    with builder() as b:
        b.build()


if __name__ == '__main__':

    from optparse import OptionParser

    parser = OptionParser()
    options, args = parser.parse_args()

    if not len(args):
        allowed = builders.keys()
        allowed.append('all')
        print "Please specify one of %s" % allowed
        exit()

    platform = args.pop(0)

    if platform == 'all':
        for p in builders.keys():
            build(p)
    else:
        build(platform)
