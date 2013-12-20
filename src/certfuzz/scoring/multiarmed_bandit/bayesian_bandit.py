'''
Created on Feb 22, 2013

@organization: cert.org
'''
from certfuzz.fuzztools.probability import weighted_choice
from . import MultiArmedBanditBase
from .arms.bayes_laplace import BanditArmBayesLaplace

class BayesianMultiArmedBandit(MultiArmedBanditBase):
    '''
    Bayesian arms, weighted choice proportionate to each arm's share
    of the total across all arms.
    '''
    arm_type = BanditArmBayesLaplace

    @property
    def _scaled_scores(self):
        scaled_scores = {}
        total = self._total_p

        for key, arm in self.arms.iteritems():
            score = arm.probability / total
            scaled_scores[key] = score
        return scaled_scores

    def _next_key(self):
        return weighted_choice(self._scaled_scores)

    def __iter__(self):
        return self

    def next(self):
        key = self._next_key()
        return self.things[key]
