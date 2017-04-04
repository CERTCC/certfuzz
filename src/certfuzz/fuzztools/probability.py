'''
Created on Sep 23, 2010

@organization: cert.org@cert.org

A collection of probability functions to assist in fuzzing. Most likely the thing you're
looking for is how_many_misses_until_quit().
'''
import random
import math


def beta_estimate(m, N, a_prior=1.0, b_prior=1.0):
    numerator = alpha = m + a_prior
    l = N - m
    denominator = m + a_prior + l + b_prior
    beta = denominator - alpha
    p_success = float(numerator) / float(denominator)
    return (alpha, beta, p_success)


def weighted_choice(probabilities):
    '''
    Given a dict containing keys and probability values, return
    a key based on picking from the weighted values.
    @param probabilities: a dict
    '''
    x = random.uniform(0, 1)
    cumulative_probability = 0.0
    for (k, p) in probabilities.items():
        cumulative_probability += p
        if x < cumulative_probability:
            return k


def lnfactorial(x):
    '''
    Returns ln(x!) as a float.
    '''
    return math.lgamma(x + 1)


def shot_size(N, p):
    '''
    Given the size of (number of elements in) a target space and the probability
    of changing an element in that space, return the average number of elements
    that will be changed.

    For example, if you're fuzzing an N-bit file with probability p of changing
    any given bit, shot_size(N,p) will return the average number of bits that
    will be altered.
    '''
    return int(math.floor(p * N))


def misses_until_quit(c, p):
    '''
    Returns the number of times you can miss before concluding with confidence c that
    the true value of P must be lower than p.

    @param c: The desired confidence level
    @param p: The probability of a hit in a single try
    '''
    x = (math.log(1 - c) / math.log(1 - p))

    return int(math.ceil(x))


def p_max_hit(x, c=0.95):
    '''
    Return the maximum probability of getting a hit that is consistent
    at confidence level c that you could have missed x times. (If you missed
    x times, you are confident at level c that the true p is less than p_max_hit.)
    @param x: The number of tries
    @param c: The desired confidence level
    '''
    p = 1.0 - pow((1.0 - c), (1.0 / x))
    return p


class FuzzRun:
    '''
    Calculates various probabilities related to a fuzz run given:
        N = size of space (in bits)
        M = size of target (in bits)
        p = probability of changing a bit (fuzzing) OR
        p = probability of keeping a crasher bit (1 - p_revert_to_seed)

    This also works if you're consistent about using all bytes instead of bits.
    Just make sure your tools are thinking that way too.
    '''

    def __init__(self, N, M, p):
        self.N = N
        self.M = M
        self.p = p
        self.s = shot_size(self.N, self.p)
        self.check_params()
        self.p_hit = 0
        self.p_miss = 0
        self.confidence = {}

    def check_params(self):
        assert self.N > 0
        assert self.p > 0.0
        assert self.p < 1.0
        assert self.M <= self.N

        # you can't hit a target bigger than the shot you're taking
        assert self.M <= self.s

    def ln_P(self):
        '''
        Return the natural log (ln) of the probability of a hit (as a float) given:
            N = size of space (in bits)
            M = size of target (in bits)
            p = probability of changing a bit (fuzzing) OR
            p = probability of keeping a crasher bit (1 - p_revert_to_seed)
        '''
        return lnfactorial(self.s) + lnfactorial(self.N - self.M) - lnfactorial(self.N) - lnfactorial(self.s - self.M)

    def P_hit(self):
        '''
        Return the probability of hitting a target (as a float)
        '''
        if not self.p_hit:
            self.p_hit = math.exp(self.ln_P())

        return self.p_hit

    def P_miss(self):
        '''
        Return the probability of missing a target (as a float) given:
            N = size of space (in bits)
            M = size of target (in bits)
            p = probability of changing a bit (fuzzing) OR
            p = probability of keeping a crasher bit (1 - p_revert_to_seed)
        '''
        if not self.p_miss:
            self.p_miss = (1 - self.P_hit())

        return self.p_miss

    def how_many_misses_until_quit(self, confidence):
        '''
        Return the number of misses you should expect before concluding with a
        given confidence that there is less than one target remaining, given:
            confidence = the degree of confidence you desire (0.0 < c < 1.0)
            N = size of space (in bits)
            M = size of target (in bits)
            p = probability of changing a bit (fuzzing) OR
            p = probability of keeping a crasher bit (1 - p_revert_to_seed)
        '''
        if not self.confidence.get(confidence):
            assert confidence > 0.0
            assert confidence < 1.0

            if (self.P_hit() == 0):
                # you don't have a chance, so quit now
                return 0

            if (self.P_hit() == 1):
                # it's a sure thing
                return 1

            self.confidence[confidence] = misses_until_quit(confidence, self.P_hit())

        return self.confidence[confidence]

    def should_I_stop_yet(self, miss_count, confidence):
        if miss_count < self.how_many_misses_until_quit(confidence):
            return False
        else:
            return True
