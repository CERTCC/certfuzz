'''
Created on Aug 1, 2013

@organization: cert.org
'''
from ..errors import CERTFuzzError


class CampaignError(CERTFuzzError):
    pass


class AndroidCampaignError(CampaignError):
    pass


class CampaignScriptError(CampaignError):
    pass
