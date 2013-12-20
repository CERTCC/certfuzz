'''
Created on Jan 4, 2013

@organization: cert.org
'''
import logging
import os
import tempfile
import shutil
import uuid

#from certfuzz.helpers import random_str

from ..api.defaults import inifile, avddir
from .errors import AvdClonerError
from certfuzz.android.api.android_cmd import AndroidCmd

logger = logging.getLogger(__name__)
clone_name = '{}-clone-{}'.format

def clone_avd(src=None, dst=None, remove=False):
    '''
    Given the name of an Android Virtual Device, clone it and return the
    name of the new clone.

    :param src:
    :param dst:
    '''

    with AvdCloner(src=src, dst=dst, remove=remove) as cloner:
        cloner.clone()
    return cloner.dst

class AvdCloner(object):
    '''
    Provides ability to clone an Android Virtual Device.
    '''
    def __init__(self, src=None, dst=None, remove=True):
        self.src = src
        self.remove = remove
        if dst is not None:
            self.dst = dst
        else:
            # TODO: Reconsider how to generate unique clone names. This
            # is simply a trivial method, but may not be ideal.  This
            # was used in place of certfuzz.helpers.misc.random_str()
            # because that method was returning the same string for
            # each AvdCloner within a process.
            uniq_id = str(uuid.uuid4())
            self.dst = clone_name(src, uniq_id[0:15])
        self._removables = []

        self._src_avddir = None
        self._dst_avddir = None
        self._src_inifile = None
        self._dst_inifile = None

    def __enter__(self):
        if self.src is None:
            raise AvdClonerError('src avd not specified')

        self._set_paths()

        return self

    def __exit__(self, etype, value, traceback):
        if etype is not None:
            logger.debug('caught %s: %s', etype, value)

        if etype is shutil.Error:
            raise AvdClonerError(value)

        if self.remove:
            self._remove()

    def _remove(self):
        '''
        Removes the cloned avd dir and ini file
        '''
        AndroidCmd().delete(self.dst)

        # forcibly remove whatever the above missed
        for path in self._removables:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                try:
                    os.remove(path)
                except OSError as e:
                    if not os.path.exists(path):
                        # remove failed, but the file is gone anyway so it's ok
                        pass
                    else:
                        raise e

    def _set_paths(self):
        if not self.src:
            raise AvdClonerError('Cannot set paths when src is not set')
        self._src_avddir = avddir(self.src)
        self._src_inifile = inifile(self.src)

        if not self.dst:
            raise AvdClonerError('Cannot set paths when dst is not set')
        self._dst_avddir = avddir(self.dst)
        self._dst_inifile = inifile(self.dst)

    def _clone_avd_dir(self):
        '''
        Copies the avd dir
        :param src:
        :param dst:
        '''
        s = self._src_avddir
        d = self._dst_avddir
        logger.debug('Copy %s to %s', s, d)
        shutil.copytree(s, d)
        self._removables.append(d)

    def _clone_ini_file(self):
        s = self._src_inifile
        d = self._dst_inifile
        logger.debug('Copy %s to %s', s, d)
        shutil.copy(s, d)
        self._removables.append(d)

    def _fix_ini(self):
        '''
        Replaces the path contained in $AVD_HOME/<dst>.ini with $AVD_HOME/<dst>.avd
        :param dst:
        '''
        cfgpath = self._dst_inifile
        logger.debug('Fixing %s', cfgpath)
        with open(cfgpath, 'rb') as infp:
            outfp, outname = tempfile.mkstemp(suffix='.ini', dir=self._dst_avddir, text=True)
            for line in infp.readlines():
                if line.startswith('path='):
                    # replace path line
                    newpath = 'path={}\n'.format(self._dst_avddir)
                    logger.debug('...replacing %s', line.strip())
                    logger.debug('...with %s', newpath.strip())
                    os.write(outfp, newpath)
                else:
                    os.write(outfp, line)
            os.close(outfp)
        logger.debug('Move %s -> %s', outname, cfgpath)
        shutil.move(outname, cfgpath)

    def clone(self):
        '''
        Clone the avd from src->dst. Hint: use in a
        with AvdCloner(...) as c:
            c.clone()
        '''
        logger.debug('clone {} -> {}'.format(self.src, self.dst))
        self._clone_avd_dir()
        self._clone_ini_file()
        self._fix_ini()

def main():
    import argparse

    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--debug', help='', action='store_true')
    group.add_argument('-v', '--verbose', help='', action='store_true')
    parser.add_argument('src_avd',
                        help='The short name of the Android Virtual Device '
                        'to clone from', default='new_demo')
    parser.add_argument('dst_avd',
                        help='The short name of the Android Virtual Device '
                        'to copy to', default='demo_copy')
    parser.add_argument('remove', help='Remove clone after creation',
                        action='store_true')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    with AvdCloner(src=args.src_avd, dst=args.dst_avd,
                   remove=args.remove) as cloner:
        cloner.clone()

if __name__ == '__main__':
    main()
