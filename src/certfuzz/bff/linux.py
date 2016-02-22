'''
Created on Jan 13, 2014

@author: adh
'''
import logging
import os

from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport

from certfuzz.bff.common import BFF
from certfuzz.campaign.campaign_linux import LinuxCampaign


logger = logging.getLogger(__name__)


def main():
    cfg = os.path.abspath(os.path.join(os.getcwd(), 'configs', 'bff.yaml'))

    with BFF(config_path=cfg, campaign_class=LinuxCampaign) as bff:
        bff()
