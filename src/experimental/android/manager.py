'''
Created on Dec 12, 2012

@organization: cert.org
'''
import time
import os
import logging
from emu_cloner import EmulatorClone

logger = logging.getLogger()

boot_time_offset = 30
naptime = lambda x: x * boot_time_offset

def main():
    with EmulatorClone(from_avd='new_demo') as emu:
        emu.run()

def drone(drone_id):
    hdlr = logging.FileHandler('emu-%d.log' % os.getpid())
    logger.addHandler(hdlr)

    timer = naptime(drone_id)
    msg = "[DRONE-{:d} PID={:d} sleep={:d}]".format(drone_id, os.getpid(), timer)
    logger.info(msg)
    # wait for a bit before continuing
    # this is intended to help avoid cpu saturation on startup
    time.sleep(timer)

    main()

if __name__ == '__main__':
    main()
