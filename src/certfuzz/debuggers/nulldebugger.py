'''
Created on Feb 27, 2012

@author: adh
'''
from . import Debugger
import logging

# import things needed to inject randomness
import random
from . import allowed_exploitability_values
from ..helpers import random_str
from . import register

logger = logging.getLogger(__name__)


def factory(*args):
    return NullDebugger(*args)


class NullDebugger(Debugger):
    '''
    classdocs
    '''

    def debug(self, *args, **kwargs):
        logger.debug('Args: %s', args)
        logger.debug('KwArgs: %s', kwargs)
        # Flip a coin for whether this is a crash
        self.result['debug_crash'] = bool(random.randint(0, 1))
        # append a random string so we'll limit duplicates
        self.result['crash_hash'] = 'fake_crash_%s' % random_str(len=1)

        # pick a random exploitability value
        self.result['exp'] = random.choice(allowed_exploitability_values)
        self.debugger_output = 'How many bugs would a debugger debug if a debugger could debug bugs?'
        self.type = 'fake'
        self.seedfile = 'seedfile'
        self.seed = 'seed'
        self.faddr = 'faddr'
        # Flip a coin for heisenbuggery
        self.is_heisenbug = bool(random.randint(0, 1))
        return self.result

register(NullDebugger)
