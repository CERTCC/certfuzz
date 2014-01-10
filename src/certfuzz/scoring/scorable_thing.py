'''
Created on Mar 26, 2012

@organization: cert.org
'''
import json
from ..helpers import random_str


def beta_estimate(m, N, a_prior=1.0, b_prior=1.0):
    numerator = alpha = m + a_prior
    l = N - m
    denominator = m + a_prior + l + b_prior
    beta = denominator - alpha
    p_success = float(numerator) / float(denominator)
    return (alpha, beta, p_success)


class ScorableThing(object):
    def __init__(self, key=None, a=None, b=None, uniques_only=True):
        '''

        All parameters are optional
        @param key: A string to associate with this thing
        @param a: parameter for Beta distribution
        @param b: parameter for Beta distribution
        @param uniques_only: If False, count all successes. Otherwise count
        only unique ones.
        '''
        if not key:
            self.key = 'scorable_thing_' + random_str(8)
        else:
            self.key = key

        self.a = a or 1
        self.b = b or 1
        self.uniques_only = uniques_only
        self.seen = {}
        self.successes = 0
        self.tries = 0
        self.probability = beta_estimate(0, 0, self.a, self.b)[2]

    def __repr__(self):
        return self.key

    def record_failure(self, tries=1):
        '''
        Convenience method for recording failed trials
        @param tries: number of trials
        '''
        self.record_tries(tries)

    def record_tries(self, tries=0):
        self.record_result(0, tries)

    def record_success(self, key, tries=1):
        '''
        Convenience method for recording successful trials
        @param key: a key (string) of the thing you're recording
        @param successes: number of successes
        @param tries: number of trials
        '''
        is_new = False
        try:
            self.seen[key] += 1
        except KeyError:
            self.seen[key] = 1
            is_new = True

        if is_new or not self.uniques_only:
            # this one is new, so update the stats
            self.record_result(1, tries)
        else:
            self.record_failure(tries)

    def record_result(self, successes=0, tries=0):
        '''
        Records successes or failures.

        @param successes: number of successes
        @param tries: number of trials
        '''

        self.successes += successes
        self.tries += tries
        self.update(m=successes, N=tries)

    def update(self, m=0, N=0):
        a, b, p = beta_estimate(m, N, self.a, self.b)
        self.a = a
        self.b = b
        self.probability = p

    def doubt(self, factor=None):
        '''
        Refactor a and b parameters, reducing them by the specified
        factor (defaults to using the value of a as the factor, such that
        a becomes 1 and b becomes b/a). Will always prefer the lesser of the
        factor specified or the current value of a. (can't wind up with a < 1).

        This has the effect of maintaining the probability, but allowing new
        observations to influence our estimated parameters more than they would
        have otherwise. Essentially, it allows us to more easily reconfirm or
        adjust our beliefs by injecting doubt in what we think we know.

        @param factor: the factor to divide by
        '''
        import math

        if not factor:
            _factor = float(self.a)
        else:
            _factor = float(min((factor, self.a)))

        self.a = int(math.ceil(self.a / _factor))
        self.b = int(math.ceil(self.b / _factor))

    def __getstate__(self):
        return self.__dict__.copy()

    def to_json(self, sort_keys=True, indent=None):
        state = self.__getstate__()
        return json.dumps(state, sort_keys=sort_keys, indent=indent)
