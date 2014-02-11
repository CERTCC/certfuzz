'''
Created on Feb 10, 2014

@organization: cert.org
'''
import logging
from .linux.linux_build2 import LinuxBuild
from .osx.darwin_build2 import DarwinBuild
from .errors import BuildError


logger = logging.getLogger(__name__)


SUPPORTED_PLATFORMS = {'linux': LinuxBuild,
                     'windows': None,
                     'darwin': DarwinBuild,
                     }


def builder_for(platform):
    '''
    Factory method that returns the appropriate Build class for the platform requested
    :param platform:
    '''
    try:
        return SUPPORTED_PLATFORMS[platform]
    except KeyError:
        raise BuildError('Unsupported platform: {}'.format(platform))
