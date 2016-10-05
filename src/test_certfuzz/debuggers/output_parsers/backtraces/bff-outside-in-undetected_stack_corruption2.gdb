[Thread debugging using libthread_db enabled]

Program received signal SIGSEGV, Segmentation fault.
0xb77dad66 in CM7_ParseFile () from /usr/local/lib/imcmx2.flt
process 32515
cmdline = '/usr/local/bin/exsimple'
cwd = '/home/fuzz'
exe = '/usr/local/bin/exsimple'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8060000    0x18000          0      /usr/local/bin/exsimple
	 0x8060000  0x8062000     0x2000    0x17000      /usr/local/bin/exsimple
	 0x8062000  0x80cf000    0x6d000          0           [heap]
	0xb7741000 0xb77c9000    0x88000          0      /usr/local/lib/isunx2.flt
	0xb77c9000 0xb77d0000     0x7000    0x88000      /usr/local/lib/isunx2.flt
	0xb77d0000 0xb77f7000    0x27000          0      /usr/local/lib/imcmx2.flt
	0xb77f7000 0xb77f8000     0x1000    0x27000      /usr/local/lib/imcmx2.flt
	0xb77f8000 0xb780a000    0x12000          0      /usr/local/lib/libvs_gdsf.so
	0xb780a000 0xb780c000     0x2000    0x11000      /usr/local/lib/libvs_gdsf.so
	0xb780c000 0xb7831000    0x25000          0        
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
ecx            0x808d0c8	134795464
edx            0x0	0
ebx            0xb77f7ae0	-1216382240
esp            0xbffe4480	0xbffe4480
ebp            0x808d358	0x808d358
esi            0x20	32
edi            0x8	8
eip            0xb77dad66	0xb77dad66 <CM7_ParseFile+86>
eflags         0x10246	[ PF ZF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
Dump of assembler code from 0xb77dad46 to 0xb77dad66:
0xb77dad46 <CM7_ParseFile+54>:	mov    DWORD PTR [esp+0x24],eax
0xb77dad4a <CM7_ParseFile+58>:	mov    eax,DWORD PTR [ebx-0x728]
0xb77dad50 <CM7_ParseFile+64>:	mov    DWORD PTR [esp+0x28],eax
0xb77dad54 <CM7_ParseFile+68>:	xor    eax,eax
0xb77dad56 <CM7_ParseFile+70>:	mov    DWORD PTR [esp+0x2c],eax
0xb77dad5a <CM7_ParseFile+74>:	xor    eax,eax
0xb77dad5c <CM7_ParseFile+76>:	mov    DWORD PTR [esp+0x30],eax
0xb77dad60 <CM7_ParseFile+80>:	mov    eax,DWORD PTR [ebp+0x800]
End of assembler dump.
Dump of assembler code from 0xb77dad66 to 0xb77dad86:
0xb77dad66 <CM7_ParseFile+86>:	mov    BYTE PTR [eax+0x14],0xff
0xb77dad6a <CM7_ParseFile+90>:	mov    eax,DWORD PTR [ebp+0x800]
0xb77dad70 <CM7_ParseFile+96>:	mov    BYTE PTR [eax+0x18],0xff
0xb77dad74 <CM7_ParseFile+100>:	mov    eax,DWORD PTR [ebp+0x800]
0xb77dad7a <CM7_ParseFile+106>:	mov    BYTE PTR [eax+0x1c],0xff
0xb77dad7e <CM7_ParseFile+110>:	mov    eax,DWORD PTR [ebp+0x800]
0xb77dad84 <CM7_ParseFile+116>:	mov    DWORD PTR [eax],0x1
End of assembler dump.
#0  0xb77dad66 in CM7_ParseFile () from /usr/local/lib/imcmx2.flt
No symbol table info available.
#1  0x01948ae5 in ?? ()
No symbol table info available.
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
siginfo:$1 = {si_signo = 11, si_errno = 0, si_code = 1, _sifields = {_pad = {
      20, -1216500378, 138185880, -1212340810, 0, 0, 139408452, -1073744232, 
      135528116, -1216500378, 0, 5, 145770968, 0, 0, -1, -1216500378, 0, 
      32515, 0, 0, 0, -1073743996, -1211595803, -1211595774, 0, 0, 0, 0}, 
    _kill = {si_pid = 20, si_uid = 3078466918}, _timer = {si_tid = 20, 
      si_overrun = -1216500378, si_sigval = {sival_int = 138185880, 
        sival_ptr = 0x83c8c98}}, _rt = {si_pid = 20, si_uid = 3078466918, 
      si_sigval = {sival_int = 138185880, sival_ptr = 0x83c8c98}}, _sigchld = {
      si_pid = 20, si_uid = 3078466918, si_status = 138185880, 
      si_utime = -1212340810, si_stime = 0}, _sigfault = {si_addr = 0x14}, 
    _sigpoll = {si_band = 20, si_fd = -1216500378}}}
si_addr:$2 = (void *) 0x14
A debugging session is active.

	Inferior 1 [process 32515] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
