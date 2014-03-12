'''
Created on Feb 28, 2013

@organization: cert.org
'''
import logging

from certfuzz.android.api.defaults import sdk_platform_tool
from certfuzz.android.api.errors import AaptError
from certfuzz.fuzztools.command_line_callable import CommandLineCallable


logger = logging.getLogger(__name__)


class Aapt(CommandLineCallable):
    def __init__(self, sdk_path='~/android-sdk'):
        CommandLineCallable.__init__(self, ignore_result=False)
        self.arg_pfx = [sdk_platform_tool('aapt')]

    def dump(self, what, path_to_apk, assets=None, values=False):
        args = []
        if values:
            args.append('--values')
        if not what in ['badging', 'permissions', 'resources',
                        'configurations', 'xmltree', 'xmlstrings']:
            raise AaptError('Unknown dump option: %s', what)
        args.append('d')
        args.append(what)
        args.append(path_to_apk)
        if assets:
            args.extend(assets)
        self.call(args)

    def get_manifest(self, path_to_apk):
        logger.debug('get manifest from %s', path_to_apk)
        self.dump(what='xmltree', path_to_apk=path_to_apk, assets=['AndroidManifest.xml'])
