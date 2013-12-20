'''
Created on Feb 28, 2013

@organization: cert.org
'''
import logging
import tempfile
import shutil

logger = logging.getLogger(__name__)


class TempDir(object):
    '''
    Runtime context that creates a tempdir then cleans it up when exiting the
    context. Make sure you copy out what you need to keep before leaving the
    context.
    '''
    def __init__(self, suffix=None, prefix=None, dir=None):
        self.suffix = suffix
        self.prefix = prefix
        self.dir = dir
        self.tmpdir = None

    def __enter__(self):
        kwargs = {}
        for key in ['suffix', 'prefix', 'dir']:
            value = getattr(self, key)
            if value:
                kwargs[key] = value

        self.tmpdir = tempfile.mkdtemp(**kwargs)
        logger.debug('Created tempdir %s', self.tmpdir)
        return self.tmpdir

    def __exit__(self, etype, value, traceback):
        if etype is not None:
            logger.debug('%s caught %s: %s', self.__class__.__name__, etype, value)
        logger.debug('Removing tempdir %s', self.tmpdir)
        shutil.rmtree(self.tmpdir, ignore_errors=True)
