'''
Created on Feb 22, 2013

@organization: cert.org
'''
from certfuzz.scoring.multiarmed_bandit.arms.base import BanditArmBase


class BanditArmBayesLaplace(BanditArmBase):
    '''
    This class implements a Bayesian estimator on a Bernoulli process where
    each pull of the arm results in either a success with probability p.

    Uses Laplace's Law of Succession
    '''

    def _update_p(self, *_unused_args):
        # sometimes successes can get ahead of trials before catching up
        # later in the same iteration. This line ensures that we never try
        # to calculate a number that will end up >1.0 (fixes BFF-521)
        trials = max(self.trials, self.successes)

        # see Laplace's Law of Succession
        self.probability = (self.successes + 1.0) / (trials + 2.0)
