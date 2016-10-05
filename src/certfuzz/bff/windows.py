'''
Created on Jan 13, 2014

@author: adh
'''

import logging
import os

from certfuzz.campaign.campaign_windows import WindowsCampaign

from certfuzz.bff.common import BFF


logger = logging.getLogger(__name__)


def main():
    cfg = os.path.abspath(os.path.join(os.getcwd(), 'configs', 'bff.yaml'))

    with BFF(config_path=cfg, campaign_class=WindowsCampaign) as bff:
        bff()
