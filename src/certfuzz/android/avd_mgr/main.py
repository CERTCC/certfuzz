#!/usr/bin/env python
'''
Created on Jan 14, 2013

@organization: cert.org
'''
import logging
import os
import atexit

from certfuzz.android.avd_mgr import AndroidEmulator
from certfuzz.android.avd_mgr import AvdCloner
from certfuzz.android.avd_mgr import OrphanCatcher

logger = logging.getLogger(__name__)

paths_to_clean_up = set()


def _on_exit():
    # make sure we clean up
    for path in paths_to_clean_up:
        try:
            logger.debug('Removing %s', path)
            os.remove(path)
        except OSError as e:
            # it's only a problem if we're leaving behind a file
            if os.path.exists(path):
                logger.error('Error removing %s: %s', path, e)


def _write_handle(handle, pipe):
    msg = '%s\n' % handle
    os.write(pipe, msg)
    os.close(pipe)


def lifecycle(avd, pipe, poll_interval=5):
    '''
    Starts an avd, then goes into a permanent polling mode awaiting
    an exception to be thrown.
    :param avd:
    :param destroy_on_kill:
    '''
    logger.debug('starting emulator lifecycle')
#     handleable_exc = [AndroidEmulatorError, KeyboardInterrupt, SystemExit]
    handleable_exc = None
    with OrphanCatcher(avd,
                       interval=poll_interval,
                       handled_exceptions=handleable_exc) as orphan_catcher:
        with avd:
            avd.start()
            logger.info('Started %s as %s', avd.avd, avd.handle)
            if pipe:
                _write_handle(avd.handle, pipe)
            orphan_catcher.poll()


def avd_manager(emulator_opts, hide=False, pipe=None):
    logger.debug('create emulator object')
    emulator = AndroidEmulator(emulator_opts)

    clone = emulator_opts['clone']
    avd = emulator_opts['avd_name']

    if clone:
        logger.debug('cloning emulator %s', avd)
        with AvdCloner(src=avd, remove=False) as cloner:
            cloner.clone()
        emulator.avd = cloner.dst
        emulator.destroy_on_kill = True
    else:
        emulator.avd = avd

    if hide:
        emulator.no_window = True

    # if we create a clone, destroy it
    lifecycle(emulator, pipe, poll_interval=emulator_opts['orphan_check_interval'])


def main():
    '''
    Entry point for bff_avd_mgr
    '''
    import argparse
    atexit.register(_on_exit)

    logger = logging.getLogger()
    hdlr = logging.StreamHandler()
    logger.addHandler(hdlr)

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--debug', help='', action='store_true')
    group.add_argument('-v', '--verbose', help='', action='store_true')
    parser.add_argument('avd',
                        help='The short name of the Android Virtual Device',
                        type=str)
    parser.add_argument('--hide', help='Hides emulator window', action='store_true',
                        default=False)
    parser.add_argument('--clone', help='Clone the avd first, then run the clone',
                         action='store_true', default=False)
    parser.add_argument('--emu_hdir', help='Directory to write emulator handles to',
                        type=str, default='.')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    avd_manager(args.avd, args.clone, args.hide, args.emu_hdir)

if __name__ == '__main__':
    main()
