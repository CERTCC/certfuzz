"""This 'just in time debugger' module terminates the "fuzzjob" job object
when called with an ACCESS_VIOLATION return code as a signal to the main
fuzzer that an exception occurred.

"""
import sys
from ctypes import windll, byref
from ctypes.wintypes import HANDLE, BOOL, LPCWSTR


def main(pid=None):
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_INFORMATION = 0x0400
    JOB_OBJECT_ALL_ACCESS = 0x1F001F
    hProc = HANDLE()
    result = BOOL()
    kernel32 = windll.kernel32
    hProc = kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
        None, pid)
    hJobObject = kernel32.OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, 1,
        LPCWSTR("fuzzjob"))
    if hJobObject == None:
        # this process is not in the fuzzjob, bail
        exit()
    kernel32.IsProcessInJob(hProc, hJobObject, byref(result))
    if result.value:
        kernel32.TerminateJobObject(hJobObject, 0xC0000005)

#else:
#    pass

if __name__ == "__main__":
    # crash pid
    pid = int(sys.argv[1])
    main(pid)
