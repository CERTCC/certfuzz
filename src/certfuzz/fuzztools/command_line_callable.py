'''
Created on Mar 6, 2013

@organization: cert.org
'''
import logging
import subprocess

logger = logging.getLogger(__name__)


class CommandLineCallable(object):
    '''
    Class intended mainly for binding a python API to an underlying command
    line utility.

    Intended use:
    class MyCLI(CommandLineCallable):
        def __init__(self,debug=False):
            CommandLineCallable.__init__(self,ignore_result=False)
            self.arg_pfx = ['mycli']
            if debug:
                self.arg_pfx.append('--debug')
        def cli_command(*extra_arg_list):
            args = ['cli_command']
            args.extend(extra_arg_list)
            self.call(args)
            if self.stderr:
                raise Exception('Something has gone wrong')

    The class above thus allows you to write:
    cli=MyCLI(debug=True)
    cli.cli_command('foo','bar')
    try:
        result = cli.stdout
    except:
        for line in cli.stderr.splitlines():
            logger.warning(line)
        raise

    Which would in turn invoke:
        $ mycli --debug cli_command foo bar
    Placing stdout into cli.stdout, and raising an exception if stderr is not
    empty.
    '''
    arg_pfx = []

    def __init__(self, ignore_result=False):
        self.stdout = ''
        self.stderr = ''
        if ignore_result:
            self.call = self._call
        else:
            self.call = self._call_stdout_stderr

    def _call(self, args):
        # TODO: do we need a p.wait() here?
        arglist = self.arg_pfx + args
        logger.debug(' '.join(arglist))
        subprocess.call(arglist)

    def _call_stdout_stderr(self, args):
        arglist = self.arg_pfx + args
        logger.debug(' '.join(arglist))
        p = subprocess.Popen(arglist,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (self.stdout, self.stderr) = p.communicate()
