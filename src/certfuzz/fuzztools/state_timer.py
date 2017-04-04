'''
Created on Jan 3, 2014

@author: adh
'''
import time


class StateTimer(object):
    '''
    Implements a timer with multiple states
    '''
    def __init__(self, states=None):
        self.current_state = None
        self.timers = {}
        self._in = None
        self._delim = ', '

    def __str__(self):
        return 'State Timer - ' + self._delim.join('{}: {}'.format(k, v) for k, v in self.timers.items())

    def _reset(self):
        self.current_state = None
        self._in = None

    def states(self):
        return list(self.timers.keys())

    def enter_state(self, new_state=None):
        if new_state == self.current_state:
            # nothing to do
            return
        # state change
        # close out current timer
        if self.current_state is not None:
            _out = time.time()
            _elapsed = _out - self._in
            self.timers[self.current_state] += _elapsed

        # start new timer
        if new_state is None:
            self._reset()
        else:
            self.current_state = new_state
            self._in = time.time()
            if not self.current_state in self.timers:
                self.timers[self.current_state] = 0.0

    def total_time(self):
        return sum(self.timers.values())

    def time_in(self, state):
        if state in self.timers:
            return self.timers[state]
        else:
            return 0.0

STATE_TIMER = StateTimer()
