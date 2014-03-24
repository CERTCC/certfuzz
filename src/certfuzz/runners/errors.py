'''
Created on Oct 23, 2012

@organization: cert.org
'''
from certfuzz.errors import CERTFuzzError


class RunnerError(CERTFuzzError):
    pass


class RunnerArchitectureError(RunnerError):
    pass


class RunnerPlatformVersionError(RunnerError):
    pass


class RunnerRegistryError(RunnerError):
    pass


class AndroidRunnerError(RunnerError):
    pass
