[Thread debugging using libthread_db enabled]

Program received signal SIGFPE, Arithmetic exception.
0xb780f790 in ?? () from /usr/local/lib/ibgp42.flt
process 11048
cmdline = '/usr/local/bin/exsimple'
cwd = '/home/fuzz'
exe = '/usr/local/bin/exsimple'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8060000    0x18000          0      /usr/local/bin/exsimple
	 0x8060000  0x8062000     0x2000    0x17000      /usr/local/bin/exsimple
	 0x8062000  0x80f0000    0x8e000          0           [heap]
	0xb777d000 0xb7805000    0x88000          0      /usr/local/lib/isunx2.flt
	0xb7805000 0xb780c000     0x7000    0x88000      /usr/local/lib/isunx2.flt
	0xb780c000 0xb7819000     0xd000          0      /usr/local/lib/ibgp42.flt
	0xb7819000 0xb781b000     0x2000     0xc000      /usr/local/lib/ibgp42.flt
	0xb781b000 0xb782d000    0x12000          0      /usr/local/lib/libvs_gdsf.so
	0xb782d000 0xb782f000     0x2000    0x11000      /usr/local/lib/libvs_gdsf.so
	0xb782f000 0xb7831000     0x2000          0        
	0xb7831000 0xb789e000    0x6d000          0      /usr/local/lib/libsc_fut.so
	0xb789e000 0xb78a7000     0x9000    0x6c000      /usr/local/lib/libsc_fut.so
	0xb78a7000 0xb78c4000    0x1d000          0      /lib/libgcc_s.so.1
	0xb78c4000 0xb78c5000     0x1000    0x1c000      /lib/libgcc_s.so.1
	0xb78c5000 0xb78d8000    0x13000          0      /usr/lib/libz.so.1.2.3.4
	0xb78d8000 0xb78d9000     0x1000    0x13000      /usr/lib/libz.so.1.2.3.4
	0xb78d9000 0xb78ec000    0x13000          0      /usr/local/lib/libsc_lo.so
	0xb78ec000 0xb78f2000     0x6000    0x12000      /usr/local/lib/libsc_lo.so
	0xb78f2000 0xb78f3000     0x1000          0        
	0xb78f3000 0xb78f5000     0x2000          0      /lib/i686/cmov/libdl-2.11.2.so
	0xb78f5000 0xb78f6000     0x1000     0x1000      /lib/i686/cmov/libdl-2.11.2.so
	0xb78f6000 0xb78f7000     0x1000     0x2000      /lib/i686/cmov/libdl-2.11.2.so
	0xb78f7000 0xb7912000    0x1b000          0      /usr/local/lib/libsc_fi.so
	0xb7912000 0xb7913000     0x1000    0x1a000      /usr/local/lib/libsc_fi.so
	0xb7913000 0xb79c3000    0xb0000          0      /usr/lib/libstdc++.so.5.0.7
	0xb79c3000 0xb79c8000     0x5000    0xaf000      /usr/lib/libstdc++.so.5.0.7
	0xb79c8000 0xb79cd000     0x5000          0        
	0xb79cd000 0xb79e0000    0x13000          0      /usr/local/lib/libwv_core.so
	0xb79e0000 0xb79e2000     0x2000    0x12000      /usr/local/lib/libwv_core.so
	0xb79e2000 0xb7d59000   0x377000          0        
	0xb7d59000 0xb7df4000    0x9b000          0      /usr/local/lib/libsc_ut.so
	0xb7df4000 0xb7df6000     0x2000    0x9a000      /usr/local/lib/libsc_ut.so
	0xb7df6000 0xb7e00000     0xa000          0        
	0xb7e00000 0xb7e07000     0x7000          0      /usr/local/lib/libsc_fa.so
	0xb7e07000 0xb7e14000     0xd000     0x6000      /usr/local/lib/libsc_fa.so
	0xb7e14000 0xb7e25000    0x11000          0      /usr/local/lib/libsc_ch.so
	0xb7e25000 0xb7e26000     0x1000    0x11000      /usr/local/lib/libsc_ch.so
	0xb7e26000 0xb7e4a000    0x24000          0      /lib/i686/cmov/libm-2.11.2.so
	0xb7e4a000 0xb7e4b000     0x1000    0x23000      /lib/i686/cmov/libm-2.11.2.so
	0xb7e4b000 0xb7e4c000     0x1000    0x24000      /lib/i686/cmov/libm-2.11.2.so
	0xb7e4c000 0xb7e61000    0x15000          0      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7e61000 0xb7e62000     0x1000    0x14000      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7e62000 0xb7e63000     0x1000    0x15000      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7e63000 0xb7e65000     0x2000          0        
	0xb7e65000 0xb7fa5000   0x140000          0      /lib/i686/cmov/libc-2.11.2.so
	0xb7fa5000 0xb7fa6000     0x1000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7fa6000 0xb7fa8000     0x2000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7fa8000 0xb7fa9000     0x1000   0x142000      /lib/i686/cmov/libc-2.11.2.so
	0xb7fa9000 0xb7fad000     0x4000          0        
	0xb7fad000 0xb7fc9000    0x1c000          0      /usr/local/lib/libsc_da.so
	0xb7fc9000 0xb7fca000     0x1000    0x1b000      /usr/local/lib/libsc_da.so
	0xb7fca000 0xb7fd3000     0x9000          0      /usr/local/lib/libsc_ex.so
	0xb7fd3000 0xb7fd4000     0x1000     0x9000      /usr/local/lib/libsc_ex.so
	0xb7fe0000 0xb7fe2000     0x2000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0      /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000      /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000      /lib/ld-2.11.2.so
	0xbffdf000 0xc0000000    0x21000          0           [stack]
eax            0x0	0
ecx            0x0	0
edx            0x0	0
ebx            0xb781a824	-1216239580
esp            0xbffe45a0	0xbffe45a0
ebp            0xbffe4680	0xbffe4680
esi            0x0	0
edi            0x0	0
eip            0xb780f790	0xb780f790
eflags         0x10246	[ PF ZF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
Dump of assembler code from 0xb780f770 to 0xb780f790:
0xb780f770:	and    ecx,0x7ffc
0xb780f776:	mov    esi,ecx
0xb780f778:	imul   esi,eax
0xb780f77b:	cmp    esi,0x7fff
0xb780f781:	jbe    0xb780f788
0xb780f783:	mov    esi,0x7fff
0xb780f788:	mov    DWORD PTR [esp+0x4],esi
0xb780f78c:	xor    edx,edx
0xb780f78e:	mov    eax,esi
End of assembler dump.
Dump of assembler code from 0xb780f790 to 0xb780f7b0:
0xb780f790:	div    ecx
0xb780f792:	mov    DWORD PTR [esp],0x42
0xb780f799:	mov    DWORD PTR [esp+0x44],eax
0xb780f79d:	call   0xb780e55c <GlobalAlloc@plt>
0xb780f7a2:	mov    edi,eax
0xb780f7a4:	test   edi,edi
0xb780f7a6:	mov    eax,0xffffffff
0xb780f7ab:	je     0xb780f89c
End of assembler dump.
#0  0xb780f790 in ?? () from /usr/local/lib/ibgp42.flt
No symbol table info available.
#1  0x00000000 in ?? ()
No symbol table info available.
siginfo:$1 = {si_signo = 8, si_errno = 0, si_code = 1, _sifields = {_pad = {
      -1216284784, -1216284784, 145472152, 502, 0, 0, 139408452, -1073744232, 
      135528116, -1216284784, 0, 5, 145714736, 0, 0, -1, -1216284784, 0, 
      11048, 0, 0, 0, -1073743996, -1211595803, -1211595774, 0, 0, 0, 0}, 
    _kill = {si_pid = -1216284784, si_uid = 3078682512}, _timer = {
      si_tid = -1216284784, si_overrun = -1216284784, si_sigval = {
        sival_int = 145472152, sival_ptr = 0x8abba98}}, _rt = {
      si_pid = -1216284784, si_uid = 3078682512, si_sigval = {
        sival_int = 145472152, sival_ptr = 0x8abba98}}, _sigchld = {
      si_pid = -1216284784, si_uid = 3078682512, si_status = 145472152, 
      si_utime = 502, si_stime = 0}, _sigfault = {si_addr = 0xb780f790}, 
    _sigpoll = {si_band = -1216284784, si_fd = -1216284784}}}
si_addr:$2 = (void *) 0xb780f790
A debugging session is active.

	Inferior 1 [process 11048] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
