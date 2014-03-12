'''
Created on Jan 7, 2011

@organization: cert.org
'''
START_SEED = 0
SEED_INTERVAL = 500
MAX_SEED = 1e10


class SeedRange():
    def __init__(self, start_seed=START_SEED, interval=SEED_INTERVAL, max_seed=MAX_SEED):
        self.initial_seed = start_seed
        self.s1 = start_seed
        self.interval = interval
        self.max_seed = max_seed

        self.verify_parameters()

        self.set_s2()

    def verify_parameters(self):
        assert isinstance(self.initial_seed, int), 'initial seed must be an int'
        assert isinstance(self.s1, int), 's1 must be an int'
        assert isinstance(self.interval, int), 'seed interval must be an int'
        assert self.s1 < self.max_seed

    def set_s1_to_s2(self):
        self.s1 = self.s2

    def set_s2(self):
        self.s2 = self.s1 + self.interval

    def increment_seed(self):
        self.s1 += 1

    def in_range(self):
        return self.s1 < self.s2

    def in_max_range(self):
        return self.s1 < self.max_seed

    def bookmark_s1(self):
        self._s1_bookmark = self.s1

    def s1_delta(self):
        return self.s1 - self._s1_bookmark + 1

    def s1_s2_delta(self):
        return self.s2 - self.s1
