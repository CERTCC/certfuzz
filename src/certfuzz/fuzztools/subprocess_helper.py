'''
Created on Oct 22, 2010

Provides common methods for running and killing subprocesses.

@organization: cert.org
'''
import os
import platform
import signal
import string
import subprocess
import sys
from threading import Timer


def on_windows():
    return (platform.system() == "Windows")


def on_osx():
    return (platform.system() == "Darwin")


def on_linux():
    return (platform.system() == "Linux")

if on_windows():
    import ctypes

if on_linux():
    # gdb can cause SIGTTOU to get sent to python. We don't want python to
    # stop.
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)


def run_with_timer(args, timeout, progname, cwd=None, use_shell=False, **options):
    '''
    Runs <command_line>. If it takes longer than <timeout> we'll
    kill <command_line> as well as hunt down any processes named
    <progname>. If you want to redirect stdout and/or stderr,
    use stdout=<stdout_file> or stderr=<stderr_file> (or both).
    @return: none
    '''
    output = ''
    _seeoutput = False
    if options and options.get('seeoutput'):
        _seeoutput = True
    if options and options.get('stdout'):
        output = open(options['stdout'], 'w')
    else:
        output = open(os.devnull, 'w')

    errors = ''
    if options and options.get('stderr'):
        errors = open(options['stderr'], 'w')
    else:
        errors = open(os.devnull, 'w')

    env = None
    if options and options.get('env'):
        env = options['env']
    else:
        env = os.environ

    # remove empty args from the list [Fix for BFF-17]
    #    ['a','','b','c'] -> ['a', 'b', 'c']
    args = [arg for arg in args if arg]

    for index, arg in enumerate(args):
        args[index] = string.replace(args[index], '"', '')

    try:
        if _seeoutput:
            # os.setsid sets process group
            p = subprocess.Popen(
                args, cwd=cwd, env=env, shell=use_shell, preexec_fn=os.setsid)
        else:
            p = subprocess.Popen(
                args, cwd=cwd, stdout=output, stderr=errors, env=env, shell=use_shell, preexec_fn=os.setsid)
    except:
        print("Failed to run [%s]" % ' '.join(args))
        sys.exit(-1)

    # Set up timeout timer
    # Give extra time for the first invocation of the application
    t = Timer(timeout, _kill, args=[p, 0x00, progname])
    t.start()
    try:
        p.wait()
    except KeyboardInterrupt:
        raise
    t.cancel()

    # close our stdout and stderr filehandles

    if not _seeoutput:
        [fh.close() for fh in (output, errors)]
    return p


def _kill(p, returncode, progname):  # @UnusedVariable
    if (on_windows()):
        """_kill function for Win32"""
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(1, 1, p.pid)
        ret = kernel32.TerminateProcess(handle, returncode)
        kernel32.CloseHandle(handle)
    else:
        # Kill process group
        try:
            ret = os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except OSError:
            # Process could be dead by now
            ret = 1
        if progname:
            killall(progname, signal.SIGKILL)
    return (0 != ret)


def killall(processname, killsignal):
    '''
    Python equivalent of the killall command
    @param processname: process name to kill
    @param killsignal: signal to send to process
    '''
    assert (processname != ''), "Cannot kill a blank process name"
    if (on_osx()):
        os.system('killall -%d %s 2> /dev/null' % (killsignal, processname))
    else:
        for folder in os.listdir("/proc"):
            filename = os.path.join("/proc", folder, "cmdline")

            if not os.access(filename, os.R_OK):
                # we don't have read access, so skip it
                continue
            try:
                exename = file(filename).read().split("\x00")[0]
            except IOError:
                # just skip it if the filename isn't there anymore
                continue

            if exename != processname:
                continue
            elif (exename.find(processname) == -1):
                continue
            try:
                os.kill(int(folder), killsignal)
            except OSError:
                # skip it if the process has gone away on its own
                continue
