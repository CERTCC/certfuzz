'''
Created on Sep 9, 2011

@organization: cert.org
'''
import logging
import csv
import os
import time

from ..fuzztools.probability import weighted_choice
from .errors import ScorableSetError, EmptySetError

logger = logging.getLogger(__name__)


# Simplified reimplementation of ScorableSet with a Bayesian approach
class ScorableSet2(object):
    '''
    '''
    def __init__(self, datafile=None):
        self.things = {}
        self.scaled_score = {}
        self.datafile = datafile
        self.expected_crash_density = None

    def add_item(self, key, thing):
        if not hasattr(thing, 'probability'):
            raise ScorableSetError('Items must have a "probability" attribute.')

        self.things[key] = thing

    def del_item(self, key):
        for d in (self.things, self.scaled_score):
            try:
                del d[key]
            except KeyError:
                # if there was a keyerror, our job is already done
                pass

    def _sum_scores(self):
        return sum([thing.probability for thing in self.things.itervalues()])

    def _update_probabilities(self):
        total = self._sum_scores()

        crash_densities = []
        for key, thing in self.things.iteritems():
            p = thing.probability
            score = p / total
            self.scaled_score[key] = score
            logger.debug('probability(%s)=%f', key, score)
            crash_densities.append(p * score)
        self.expected_crash_density = sum(crash_densities)

    def next_key(self):
        if not len(self.things):
            raise EmptySetError
        self._update_probabilities()
        choice = weighted_choice(self.scaled_score)
        logger.debug('next_key=%s', choice)
        return choice

    def next_item(self):
        next_key = self.next_key()

        try:
            next_thing = self.things[next_key]
        except KeyError:
            self.del_item(next_key)
            return self.next_item()

        if not next_thing:
            # next_thing must be an actual thing
            self.del_item(next_key)
            return self.next_item()

        # if you got here, next_thing is not None
        return next_thing

    def status(self):
        status = []
        for k in sorted(self.things.keys()):
            thing = self.things[k]
            status.append((k, self.scaled_score[k], thing.successes, thing.tries, thing.probability))
        return status

    def __getstate__(self):
        state = self.__dict__.copy()
        state['scaled_score'] = self.scaled_score.copy()
        state['things'] = self.things.copy()
        for k, thing in self.things.iteritems():
            if hasattr(thing, '__getstate__'):
                state['things'][k] = thing.__getstate__()
            elif hasattr(thing, '__dict__'):
                state['things'][k] = thing.__dict__.copy()
            else:
                state['things'][k] = thing

        return state

    def _read_csv(self):
        '''
        Reads in self.datafile and returns a list of dicts from its contents.
        Assumes data is compatible with that written by csv.DictWriter()
        Returns an empty list if the file is not found or any IOErrors occur
        in opening or reading.
        '''
        if not self.datafile:
            raise ScorableSetError('Scorable Set datafile not set.')

        data = []
        if os.path.exists(self.datafile):
            try:
                with open(self.datafile, 'rb') as f:
                    reader = csv.DictReader(f)
                    data = list(reader)
            except IOError, e:
                logger.warning('Unable to read from %s, proceeding without it: %s' % (self.datafile, e))
        return data

    def update_csv(self):
        if not self.datafile:
            raise ScorableSetError('Scorable Set datafile not set.')

        row = self.scaled_score.copy()

        sorted_keys = sorted(self.scaled_score.keys())

        row['timestamp'] = time.asctime()
        sorted_keys.insert(0, 'timestamp')

        # the file doesn't exist or is empty, so create it and add headers
        if not os.path.exists(self.datafile) or not os.path.getsize(self.datafile):
            # note use of 'b' in mode. see
            # http://stackoverflow.com/questions/3191528/csv-in-python-adding-extra-carriage-return
            with open(self.datafile, 'wb') as datafile:
                writer = csv.writer(datafile)
                writer.writerow(sorted_keys)

        with open(self.datafile, 'ab') as datafile:
            writer = csv.DictWriter(datafile, fieldnames=sorted_keys)
            writer.writerow(row)
