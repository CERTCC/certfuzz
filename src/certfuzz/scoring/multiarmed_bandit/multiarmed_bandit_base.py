'''
Created on Feb 22, 2013

@organization: cert.org
'''
from .errors import MultiArmedBanditError
from .arms.base import BanditArmBase


class MultiArmedBanditBase(object):
    '''
    Implements a simple round robin iterator
    '''
    arm_type = BanditArmBase

    def __init__(self):
        self.things = {}
        self.arms = {}

    def add_item(self, key=None, obj=None):
        if key is None:
            raise MultiArmedBanditError('unspecified key for arm')
        if obj is None:
            raise MultiArmedBanditError('unspecified value for arm')
        self.things[key] = obj
        # create a new arm of the desired type
        self.arms[key] = self.arm_type()

    def record_result(self, key, successes=0, trials=0):
        arm = self.arms[key]
        arm.update(successes, trials)

    @property
    def successes(self):
        return sum([a.successes for a in self.arms.values()])

    @property
    def trials(self):
        return sum([a.trials for a in self.arms.values()])

    @property
    def _total_p(self):
        return sum([a.probability for a in self.arms.itervalues()])

    @property
    def mean_p(self):
        return self._total_p / len(self.arms)

    @property
    def mean_p_with_trials(self):
        total = 0.0
        count = 0

        for a in self.arms.itervalues():
            if not a.trials:
                continue
            total += a.probability
            count += 1
        return float(total) / count

    def __iter__(self):
        return self

    def next(self):
        raise NotImplementedError()
