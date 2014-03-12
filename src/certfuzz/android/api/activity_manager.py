'''
Created on Jan 25, 2013

@organization: cert.org
'''
from certfuzz.android.api.adb_cmd import AdbCmd
from certfuzz.android.api.errors import ActivityManagerError


def am(handle, args):
    ActivityManager(handle).go(args)


class ActivityManager(object):
    '''
    classdocs
    '''
    def __init__(self, handle=None):
        '''
        Constructor
        '''
        self.handle = handle
        self.result = None

    def go(self, args):
        arg_pfx = ['am']
        self.result = AdbCmd(self.handle).shell(arg_pfx + args)

    def start(self, intent, debug=False, wait_for_launch=False, profiler=None,
              profile_not_idle=None, repeat=None, force_stop=False,
              opengl_trace=False):
        if not intent:
            raise ActivityManagerError('Intent not specified')

        args = ['start']
        if debug:
            args.append('-D')
        if wait_for_launch:
            args.append('-W')
        if profiler:
            args.extend(['--start-profiler', profiler])
        if profile_not_idle:
            args.extend(['-P', profile_not_idle])
        if repeat:
            args.extend(['--R', repeat])
        if force_stop:
            args.append('-S')
        if opengl_trace:
            args.append('--opengl-trace')

        args.extend(intent.as_args())
        self.go(args)

    def startservice(self, intent):
        self.go(['startservice', intent])

    def force_stop(self, package):
        self.go(['force-stop', package])

    def kill(self, package):
        self.go(['kill', package])
        # check self.result.stdout or self.result.stderr here

    def kill_all(self):
        self.go(['kill-all'])

    def broadcast(self, intent):
        self.go(['broadcast', intent])

    def instrument(self, component, *options):
        raise NotImplementedError

    def profile_start(self, process, filepath):
#        am profile start <PROCESS> <FILE>
        self.go(['profile', 'start', process, filepath])

    def profile_stop(self, process):
#       am profile stop [<PROCESS>]
        self.go(['profile', 'stop', process])

    def dumpheap(self, process, filepath, flags=None):
#       am dumpheap [flags] <PROCESS> <FILE>
        args = ['dumpheap']
        for flag in flags:
            args.append(flag)
        args.extend([process, filepath])
        self.go(args)

    def set_debug_app(self, package, w=False, persistent=False):
#       am set-debug-app [-w] [--persistent] <PACKAGE>
        args = ['set-debug-app']
        if w:
            args.append('-w')
        if persistent:
            args.append('--persistent')
        args.append(package)
        self.go(args)

    def clear_debug_app(self):
#       am clear-debug-app
        self.go(['clear-debug-app'])

    def monitor(self, gdb_port=None):
#       am monitor [--gdb <port>]
        args = ['monitor']
        if gdb_port:
            args.extend(['--gdb', gdb_port])
        self.go(args)

    def screen_compat(self, package, on=True,):
#       am screen-compat [on|off] <PACKAGE>
        args = ['screen-compat']
        if on:
            args.append('on')
        else:
            args.append('off')
        args.append(package)

    def display_size(self, reset=False, m=None, n=None):
#       am display-size [reset|MxN]
        args = ['display-size']
        if reset:
            if m or n:
                raise ActivityManagerError("Can't use both reset and MxN")
            args.append('reset')
        elif m:
            if not n:
                raise ActivityManagerError("Must specify both M and N")
            args.append('%dx%d' % (m, n))
        else:
            raise ActivityManagerError("specify either reset or m,n pair")
        self.go(args)

    def to_uri(self, intent):
        #       am to-uri [INTENT]
        self.go(['to-uri', intent])

    def to_intent_uri(self, intent):
        #       am to-intent-uri [INTENT]
        self.go(['to-intent-uri', intent])
