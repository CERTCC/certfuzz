'''
Created on Feb 13, 2014

@author: adh
'''
import logging
import os

# Added as fix for BFF-434

logger = logging.getLogger(__name__)

# remember our parent process id at startup
PPID = os.getppid()


def check_ppid():
    global PPID
    current_ppid = os.getppid()

    if current_ppid != PPID:
        logger.warning(
            'Parent process ID changed from %d to %d', PPID, current_ppid)
        PPID = current_ppid
