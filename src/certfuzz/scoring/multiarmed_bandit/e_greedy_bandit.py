'''
Created on Jan 7, 2014

@organization: cert.org
'''
from certfuzz.scoring.multiarmed_bandit.multiarmed_bandit_base import MultiArmedBanditBase
from certfuzz.scoring.multiarmed_bandit.arms.bayes_laplace import BanditArmBayesLaplace
from certfuzz.scoring.multiarmed_bandit.errors import MultiArmedBanditError

import random


class EpsilonGreedyMultiArmedBandit(MultiArmedBanditBase):
    '''
    Returns a random thing from its collection based on the Epsilon-Greedy MultiArmed Bandit strategy
    http://en.wikipedia.org/wiki/Multi-armed_bandit
    '''
    arm_type = BanditArmBayesLaplace

    def __init__(self, epsilon=0.1):
        '''
        :param epsilon: fraction of time spent exploring (vs. exploiting the best performer)
        '''
        MultiArmedBanditBase.__init__(self)
        if not 0.0 < epsilon < 1.0:
            raise MultiArmedBanditError('epsilon must be between 0.0 and 1.0')

        self.e = epsilon

    def _max_keys(self):
        max_p = 0.0
        _maybe_max_k = []
        for key, arm in self.arms.items():
            if arm.probability >= max_p:
                max_p = arm.probability
                _maybe_max_k.append((key, max_p))

        # now we have a list of tuples, but the early ones might be less than max.
        # since we went through them all on the way here though we know that max_p is
        # the actual max, so all we need to do is test for that on each tuple
        max_keys = [k for (k, p) in _maybe_max_k if p == max_p]

        return max_keys

    def _all_except(self, klist):
        return [k for k in self.things.keys() if not k in klist]

    def _next_key(self):
        _max = self._max_keys()
        if random.random() <= 1.0 - self.e:
            return random.choice(_max)
        else:
            return random.choice(self._all_except(_max))

    def __next__(self):
        '''
        With probability 1-self.e, choose the best performer. Otherwise choose one of the others with equal probability
        '''
        return self.things[self._next_key()]
