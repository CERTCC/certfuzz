'''
Created on Feb 22, 2013

@organization: cert.org
'''
from .multiarmed_bandit_base import MultiArmedBanditBase
import random

class RandomMultiArmedBandit(MultiArmedBanditBase):
    '''
    Returns a random thing from its collection.
    '''
    def __iter__(self):
        return self

    def next(self):
        return random.choice(self.things.values())
