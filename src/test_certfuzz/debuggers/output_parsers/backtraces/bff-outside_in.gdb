[Thread debugging using libthread_db enabled]

Program received signal SIGSEGV, Segmentation fault.
0xb7fdd3e2 in VwStreamOpen () from /usr/local/lib/libvs_pdx.so
process 14191
cmdline = '/usr/local/bin/exsimple'
cwd = '/home/fuzz'
exe = '/usr/local/bin/exsimple'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8060000    0x18000          0      /usr/local/bin/exsimple
	 0x8060000  0x8062000     0x2000    0x17000      /usr/local/bin/exsimple
	 0x8062000  0x8083000    0x21000          0           [heap]
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
	0xb7fdb000 0xb7fdf000     0x4000          0      /usr/local/lib/libvs_pdx.so
	0xb7fdf000 0xb7fe0000     0x1000     0x4000      /usr/local/lib/libvs_pdx.so
	0xb7fe0000 0xb7fe2000     0x2000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0      /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000      /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000      /lib/ld-2.11.2.so
	0xbffdf000 0xc0000000    0x21000          0           [stack]
eax            0x8082ff8	134754296
ecx            0x8062170	134619504
edx            0x0	0
ebx            0xb7fdf2ec	-1208093972
esp            0xbffe4760	0xbffe4760
ebp            0x8081aa8	0x8081aa8
esi            0x378	888
edi            0x378	888
eip            0xb7fdd3e2	0xb7fdd3e2 <VwStreamOpen+607>
eflags         0x10206	[ PF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
Dump of assembler code from 0xb7fdd3c2 to 0xb7fdd3e2:
0xb7fdd3c2 <VwStreamOpen+575>:	mov    eax,DWORD PTR [ecx]
0xb7fdd3c4 <VwStreamOpen+577>:	sub    eax,0x1
0xb7fdd3c7 <VwStreamOpen+580>:	test   eax,eax
0xb7fdd3c9 <VwStreamOpen+582>:	mov    DWORD PTR [ecx],eax
0xb7fdd3cb <VwStreamOpen+584>:	js     0xb7fdd6ef <VwStreamOpen+1388>
0xb7fdd3d1 <VwStreamOpen+590>:	mov    eax,DWORD PTR [ecx+0x10]
0xb7fdd3d4 <VwStreamOpen+593>:	movzx  dx,BYTE PTR [eax]
0xb7fdd3d8 <VwStreamOpen+597>:	add    eax,0x1
0xb7fdd3db <VwStreamOpen+600>:	mov    DWORD PTR [ecx+0x10],eax
0xb7fdd3de <VwStreamOpen+603>:	mov    eax,DWORD PTR [esp+0x18]
End of assembler dump.
Dump of assembler code from 0xb7fdd3e2 to 0xb7fdd402:
0xb7fdd3e2 <VwStreamOpen+607>:	mov    WORD PTR [eax+0x8],dx
0xb7fdd3e6 <VwStreamOpen+611>:	lea    eax,[edi+edi*2]
0xb7fdd3e9 <VwStreamOpen+614>:	movsx  edx,WORD PTR [ebp+eax*2+0x86]
0xb7fdd3f1 <VwStreamOpen+622>:	cmp    edx,0x10
0xb7fdd3f4 <VwStreamOpen+625>:	ja     0xb7fdd6bf <VwStreamOpen+1340>
0xb7fdd3fa <VwStreamOpen+631>:	lea    eax,[ebx-0x724]
0xb7fdd400 <VwStreamOpen+637>:	mov    eax,DWORD PTR [eax+edx*4]
End of assembler dump.
#0  0xb7fdd3e2 in VwStreamOpen () from /usr/local/lib/libvs_pdx.so
No symbol table info available.
#1  0xb7facd30 in ?? ()
No symbol table info available.
siginfo:$1 = {si_signo = 11, si_errno = 0, si_code = 1, _sifields = {_pad = {
      134754304, -1208101918, 138185880, -1212340810, 0, 0, 139408452, 
      -1073744232, 135528116, -1208101918, 0, 5, 140023584, 0, 0, -1, 
      -1208101918, 0, 14191, 0, 0, 0, -1073743996, -1211595803, -1211595774, 
      0, 0, 0, 0}, _kill = {si_pid = 134754304, si_uid = 3086865378}, 
    _timer = {si_tid = 134754304, si_overrun = -1208101918, si_sigval = {
        sival_int = 138185880, sival_ptr = 0x83c8c98}}, _rt = {
      si_pid = 134754304, si_uid = 3086865378, si_sigval = {
        sival_int = 138185880, sival_ptr = 0x83c8c98}}, _sigchld = {
      si_pid = 134754304, si_uid = 3086865378, si_status = 138185880, 
      si_utime = -1212340810, si_stime = 0}, _sigfault = {
      si_addr = 0x8083000}, _sigpoll = {si_band = 134754304, 
      si_fd = -1208101918}}}
si_addr:$2 = (void *) 0x8083000
A debugging session is active.

	Inferior 1 [process 14191] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
