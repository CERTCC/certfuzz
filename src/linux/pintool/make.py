#! /usr/bin/env python
# as of 5/7/2013, the directions here don't work:
# http://software.intel.com/sites/landingpage/pintool/docs/58423/Pin/html/
import subprocess, shlex, platform, os

bin = "calltrace.so"

machine = platform.machine()
if machine == "i686":
    machine = "x86"
    srcdir = "obj-ia32"
else:
    srcdir = "obj-intel64"
src = os.path.join(srcdir, bin)
dstdir = "."
dst = os.path.join(dstdir, bin)

cmd = "make PIN_ROOT=../pin"
print(cmd)
subprocess.call(shlex.split(cmd))

cmd = "mkdir -p %s" % dstdir
print(cmd)
subprocess.call(shlex.split(cmd))

cmd = "mv %s %s" % (src, dst)
print(cmd)
subprocess.call(shlex.split(cmd))

cmd = "rm -rf %s" % srcdir
print(cmd)
subprocess.call(shlex.split(cmd))
