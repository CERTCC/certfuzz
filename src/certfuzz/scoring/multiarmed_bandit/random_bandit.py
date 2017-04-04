'''
Created on Feb 22, 2013

@organization: cert.org
'''
from certfuzz.scoring.multiarmed_bandit.multiarmed_bandit_base import MultiArmedBanditBase
import random


class RandomMultiArmedBandit(MultiArmedBanditBase):
    '''
    Returns a random thing from its collection.
    '''
    def __next__(self):
        return random.choice(list(self.things.values()))
