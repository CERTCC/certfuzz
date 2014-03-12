'''
Created on Jan 4, 2013

@organization: cert.org
'''
import logging
from certfuzz.android.api.log_helper import pfunc
from certfuzz.android.api.errors import AndroidCmdError
from certfuzz.fuzztools.command_line_callable import CommandLineCallable
from certfuzz.android.api.defaults import sdk_tool

android = sdk_tool('android')

logger = logging.getLogger(__name__)


class AndroidCmd(CommandLineCallable):
    @pfunc(logger=logger)
    def __init__(self):
        CommandLineCallable.__init__(self, ignore_result=False)
        self.arg_pfx = [android]

    @pfunc(logger=logger)
    def delete(self, avd_name=None):
        logger.debug('Deleting avd %s', avd_name)
        if not avd_name:
            raise AndroidCmdError('avd_name must be specified')
        args = ['delete', 'avd', '--name', avd_name]
        self.call(args)
        for line in self.stdout.splitlines():
            logger.info(line)
