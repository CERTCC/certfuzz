'''
Created on Feb 22, 2013

@organization: cert.org
'''
from certfuzz.fuzztools.probability import weighted_choice
from certfuzz.scoring.multiarmed_bandit.multiarmed_bandit_base import MultiArmedBanditBase
from certfuzz.scoring.multiarmed_bandit.arms.bayes_laplace import BanditArmBayesLaplace


class BayesianMultiArmedBandit(MultiArmedBanditBase):
    '''
    Bayesian arms, weighted choice proportionate to each arm's share
    of the total across all arms.
    '''
    arm_type = BanditArmBayesLaplace

    def _scaled_scores(self):
        scaled_scores = {}
        total = self._total_p

        for key, arm in self.arms.items():
            score = arm.probability / total
            scaled_scores[key] = score
        return scaled_scores

    def _next_key(self):
        return weighted_choice(self._scaled_scores())

    def __next__(self):
        # if there aren't any arms, we're done.
        if not len(self.arms):
            raise StopIteration

        key = self._next_key()
        return self.things[key]
