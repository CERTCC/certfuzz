'''
Created on Jan 15, 2013

@organization: cert.org
'''
from .. import AndroidError

class AndroidEmulatorManagerError(AndroidError):
    pass

class AvdMgrError(AndroidEmulatorManagerError):
    pass

class AvdClonerError(AndroidEmulatorManagerError):
    pass

class OrphanedProcessError(AndroidEmulatorManagerError):
    pass
