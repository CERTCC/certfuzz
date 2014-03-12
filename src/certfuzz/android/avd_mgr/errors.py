'''
Created on Jan 15, 2013

@organization: cert.org
'''
from certfuzz.android.errors import AndroidError


class AndroidEmulatorManagerError(AndroidError):
    pass


class AvdMgrError(AndroidEmulatorManagerError):
    pass


class AvdClonerError(AndroidEmulatorManagerError):
    pass


class OrphanedProcessError(AndroidEmulatorManagerError):
    pass
