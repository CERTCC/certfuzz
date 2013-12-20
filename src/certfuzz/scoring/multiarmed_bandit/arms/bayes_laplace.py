'''
Created on Feb 22, 2013

@organization: cert.org
'''
from . import BanditArmBase

class BanditArmBayesLaplace(BanditArmBase):
    '''
    This class implements a Bayesian estimator on a Bernoulli process where
    each pull of the arm results in either a success with probability p.

    Uses Laplace's Law of Succession
    '''

    def _update_p(self, successes=0, trials=0):
        # see Laplace's Law of Succession
        self.probability = (self.successes + 1.0) / (self.trials + 2.0)
