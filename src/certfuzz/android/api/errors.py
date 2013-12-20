'''
Created on Jan 15, 2013

@organization: cert.org
'''
from .. import AndroidError

class Android_API_Error(AndroidError):
    pass

class ActivityManagerError(Android_API_Error):
    pass

class AdbCmdError(Android_API_Error):
    pass

class AndroidCmdError(Android_API_Error):
    pass

class AndroidEmulatorError(Android_API_Error):
    pass

class AaptError(Android_API_Error):
    pass
