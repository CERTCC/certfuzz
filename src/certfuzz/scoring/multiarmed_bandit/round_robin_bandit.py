'''
Created on Jan 10, 2014

@author: adh
'''
import itertools
from certfuzz.scoring.multiarmed_bandit.multiarmed_bandit_base import MultiArmedBanditBase


class RoundRobinMultiArmedBandit(MultiArmedBanditBase):
    def __iter__(self):
        '''
        Implements a simple round robin iterator
        '''
        return itertools.cycle(list(self.things.values()))
