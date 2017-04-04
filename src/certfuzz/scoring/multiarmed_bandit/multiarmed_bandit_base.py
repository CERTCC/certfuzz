'''
Created on Feb 22, 2013

@organization: cert.org
'''
import logging

from certfuzz.scoring.multiarmed_bandit.errors import MultiArmedBanditError
from certfuzz.scoring.multiarmed_bandit.arms.base import BanditArmBase

logger = logging.getLogger(__name__)


class MultiArmedBanditBase(object):
    '''
    Implements a simple round robin iterator
    '''
    arm_type = BanditArmBase

    def __init__(self):
        self.things = {}
        self.arms = {}

    def arms_as_dict(self):
        return {k: dict(arm.__dict__) for k, arm in self.arms.items()}

    def add_item(self, key=None, obj=None):
        if key is None:
            raise MultiArmedBanditError('unspecified key for arm')
        if obj is None:
            raise MultiArmedBanditError('unspecified value for arm')
        logger.debug('Creating arm %s', key)
        self.things[key] = obj
        # create a new arm of the desired type
        new_arm = self.arm_type()

        # set the new arm's params based on the results we've already found
        new_arm.successes = self.successes
        new_arm.trials = self.trials

        # but don't trust those averages too strongly
        new_arm.doubt()

        # add the new arm to the set
        self.arms[key] = new_arm

    def del_item(self, key=None):
        if key is None:
            return

        for d in (self.things, self.arms):
            try:
                del(d[key])
            except KeyError:
                # if there was a keyerror, our job is already done
                pass

    def record_result(self, key, successes=0, trials=0):
        logger.debug(
            'Recording result: key=%s successes=%d trials=%d', key, successes, trials)
        arm = self.arms[key]
        arm.update(successes, trials)

    def record_tries(self, key=None, tries=1):
        self.record_result(key, successes=0, trials=tries)

    def _log_arm_p(self):
        logger.debug('Updated probabilities')
        for k, v in self.arms.items():
            logger.debug('key=%s probability=%f', k, v.probability)

    def record_success(self, key=None, successes=1):
        self.record_result(key, successes, trials=0)
        self._log_arm_p()

    @property
    def successes(self):
        return sum([a.successes for a in list(self.arms.values())])

    @property
    def trials(self):
        return sum([a.trials for a in list(self.arms.values())])

    @property
    def _total_p(self):
        return sum([a.probability for a in self.arms.values()])

    @property
    def mean_p(self):
        return self._total_p / len(self.arms)

    @property
    def mean_p_with_trials(self):
        total = 0.0
        count = 0

        for a in self.arms.values():
            if not a.trials:
                continue
            total += a.probability
            count += 1
        return float(total) / count

    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration()
