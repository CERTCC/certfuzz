'''
Created on Apr 20, 2011

@organization: cert.org
'''
import pickle as pickle
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def dump_obj_to_file(cachefile, obj):
    try:
        with open(cachefile, 'wb') as fd:
            pickle.dump(obj, fd)
            logger.debug('Wrote %s to %s', obj.__class__.__name__, cachefile)
    except (IOError, TypeError) as e:
        logger.warning(
            'Unable to write %s to cache file %s: %s', obj.__class__.__name__, cachefile, e)


def load_obj_from_file(cachefile):
    obj = None
    try:
        with open(cachefile, 'rb') as fd:
            obj = pickle.load(fd)
            logger.debug("Read saved state from %s", cachefile)
    except Exception as e:
        logger.debug("Unable to read from %s: %s", cachefile, e)
    return obj
