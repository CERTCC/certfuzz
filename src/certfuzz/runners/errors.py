'''
Created on Oct 23, 2012

@organization: cert.org
'''
class RunnerError(Exception):
    pass

class RunnerArchitectureError(RunnerError):
    pass

class RunnerPlatformVersionError(RunnerError):
    pass

class RunnerRegistryError(RunnerError):
    pass

class AndroidRunnerError(RunnerError):
    pass
