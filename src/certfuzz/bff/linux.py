'''
Created on Jan 13, 2014

@author: adh
'''
import logging
import os

from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport

from certfuzz.bff.common import BFF
from certfuzz.campaign.linux import Campaign


logger = logging.getLogger(__name__)


def main():
    cfg = os.path.abspath(os.path.join(os.getcwd(), 'conf.d', 'bff.cfg'))

    with BFF(config_path=cfg, campaign_class=Campaign) as bff:
        bff.go()
