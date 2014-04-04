'''
Created on Jan 13, 2014

@author: adh
'''

import logging
import os

from certfuzz.campaign.campaign_windows import WindowsCampaign as Campaign

from certfuzz.bff.common import BFF


logger = logging.getLogger(__name__)


class BFFWindows(BFF):
    def _setup_logging_to_file(self, logger_, fmt):
        # logging to file
        # override if option specified
        if self.options.logfile:
            logfile = self.options.logfile
        else:
            logfile = os.path.join('log', 'bff_log.txt')

        hdlr = logging.handlers.RotatingFileHandler(logfile, mode='w', maxBytes=1e7, backupCount=5)

        hdlr.setFormatter(fmt)
        hdlr.setLevel(logging.WARNING)
        # override if debug
        if self.options.debug:
            hdlr.setLevel(logging.DEBUG)
        elif self.options.verbose:
            hdlr.setLevel(logging.INFO)
        logger_.addHandler(hdlr)


def main():
    cfg = os.path.abspath(os.path.join(os.getcwd(), 'configs', 'foe.yaml'))

    with BFFWindows(config_path=cfg, campaign_class=Campaign) as bff:
        bff.go()
