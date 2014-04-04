'''
Created on Feb 22, 2013

@organization: cert.org
'''
from certfuzz.scoring.multiarmed_bandit.arms.errors import BanditArmError


class BanditArmBase(object):
    '''
    Base class for multi-armed bandit arms. The base class simply counts
    successes and trials, and maintains a constant probability of 1.0.
    '''
    def __init__(self):
        self.successes = 0
        self.trials = 0
        self.probability = None

        # initialize probability
        self.update()

    @property
    def failures(self):
        return self.trials - self.successes

    def __repr__(self):
        return '%s' % self.__dict__

    def update(self, successes=0, trials=0):
        '''
        Update total successes and trials, recalculate probability
        :param successes:
        :param trials:
        '''
        self.successes += successes
        self.trials += trials
        self._update_p(successes, trials)
        if self.probability is None:
            raise BanditArmError('probability not set')
        elif not (0.0 <= self.probability <= 1.0):
            raise BanditArmError('probability must be between 0.0 <= {:f} <= 1.0'.format(self.probability))

    def _update_p(self, *_unused_args):
        '''
        Internal method, ensure that self.probability gets assigned
        :param successes:
        :param trials:
        '''
        # implement a naive arm that maintains constant probability
        self.probability = 1.0

    def doubt(self):
        '''
        Inject doubt into the calculation by reducing trials to
        trials/successes and successes -> 1. This essentially means that you'll
        still have the same probability, but will introduce variation into the
        probability going forward if current reality has changed from the set
        you were trained under.
        '''
        if self.successes > 0:
            scaled_trials = int(float(self.trials) / float(self.successes))
            # make sure trials is at least 1
            self.trials = max(scaled_trials, 1)
            self.successes = 1
            self.update()

    def forget(self):
        '''
        Resets successes and trials to zero, then updates probability.
        '''
        self.successes = 0
        self.trials = 0
        self.update()
