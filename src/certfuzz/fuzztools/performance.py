'''
Created on Nov 11, 2010

@organization: cert.org
'''
import time
import itertools
import numpy


class TimeStamper(object):
    '''
    classdocs
    '''

    def __init__(self):
        '''
        Constructor
        '''
        self.start = time.time()
        self.timestamps = []
        self.maxkey = ''

    def timestamp(self, key):
        if not self.maxkey or key > self.maxkey:
            self.maxkey = key

        entry = (time.time(), key)
        self.timestamps.append(entry)

    def since_start(self):
        return time.time() - self.start

    def last_ts(self):
        return self.timestamps[-1][0]

    def get_timestamps(self):
        return [t[0] for t in self.timestamps]

    def relative_to_start(self):
        return [t - self.start for t in self.get_timestamps()]

    def deltas(self):
        ts = self.get_timestamps()
        return [t2 - t1 for (t1, t2) in zip(ts[:-1], ts[1:])]

    def delta_stats(self):
        '''
        Returns the mean and stdev of self.deltas()
        @param key: the key to collect stats on
        '''
        deltas = self.deltas()
        return (numpy.mean(deltas), numpy.std(deltas))  #@UndefinedVariable
