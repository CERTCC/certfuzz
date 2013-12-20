[Thread debugging using libthread_db enabled]

Program received signal SIGSEGV, Segmentation fault.
memcpy () at ../sysdeps/i386/i686/memcpy.S:75
	in ../sysdeps/i386/i686/memcpy.S
Current language:  auto
The current source language is "auto; currently asm".
process 20146
cmdline = '/usr/local/bin/ffmpeg'
cwd = '/home/fuzz'
exe = '/usr/local/bin/ffmpeg'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x87eb000   0x7a3000          0      /usr/local/bin/ffmpeg
	 0x87eb000  0x8802000    0x17000   0x7a3000      /usr/local/bin/ffmpeg
	 0x8802000  0x8d83000   0x581000          0           [heap]
	0xb7e19000 0xb7e3f000    0x26000          0        
	0xb7e3f000 0xb7f7f000   0x140000          0      /lib/i686/cmov/libc-2.11.2.so
	0xb7f7f000 0xb7f80000     0x1000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7f80000 0xb7f82000     0x2000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7f82000 0xb7f83000     0x1000   0x142000      /lib/i686/cmov/libc-2.11.2.so
	0xb7f83000 0xb7f86000     0x3000          0        
	0xb7f86000 0xb7f9b000    0x15000          0      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7f9b000 0xb7f9c000     0x1000    0x14000      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7f9c000 0xb7f9d000     0x1000    0x15000      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7f9d000 0xb7fa0000     0x3000          0        
	0xb7fa0000 0xb7fb3000    0x13000          0      /usr/lib/libz.so.1.2.3.4
	0xb7fb3000 0xb7fb4000     0x1000    0x13000      /usr/lib/libz.so.1.2.3.4
	0xb7fb4000 0xb7fd8000    0x24000          0      /lib/i686/cmov/libm-2.11.2.so
	0xb7fd8000 0xb7fd9000     0x1000    0x23000      /lib/i686/cmov/libm-2.11.2.so
	0xb7fd9000 0xb7fda000     0x1000    0x24000      /lib/i686/cmov/libm-2.11.2.so
	0xb7fe0000 0xb7fe2000     0x2000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0      /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000      /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000      /lib/ld-2.11.2.so
	0xbffeb000 0xc0000000    0x15000          0           [stack]
eax            0x0	0
ecx            0x1d53	7507
edx            0x754c	30028
ebx            0x8d709a0	148310432
esp            0xbffff7b8	0xbffff7b8
ebp            0x8d6b0e0	0x8d6b0e0
esi            0x8d714b4	148313268
edi            0x0	0
eip            0xb7eb3bb6	0xb7eb3bb6 <memcpy+70>
eflags         0x10246	[ PF ZF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
Dump of assembler code from 0xb7eb3b96 to 0xb7eb3bb6:
0xb7eb3b96 <memcpy+38>:	push   ss
0xb7eb3b97 <memcpy+39>:	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
0xb7eb3b98 <memcpy+40>:	dec    ecx
0xb7eb3b99 <memcpy+41>:	test   esi,0x3
0xb7eb3b9f <memcpy+47>:	je     0xb7eb3bad <memcpy+61>
0xb7eb3ba1 <memcpy+49>:	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
0xb7eb3ba2 <memcpy+50>:	dec    ecx
0xb7eb3ba3 <memcpy+51>:	test   esi,0x3
0xb7eb3ba9 <memcpy+57>:	je     0xb7eb3bad <memcpy+61>
0xb7eb3bab <memcpy+59>:	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
0xb7eb3bac <memcpy+60>:	dec    ecx
0xb7eb3bad <memcpy+61>:	push   eax
0xb7eb3bae <memcpy+62>:	mov    eax,ecx
0xb7eb3bb0 <memcpy+64>:	shr    ecx,0x2
0xb7eb3bb3 <memcpy+67>:	and    eax,0x3
End of assembler dump.
Dump of assembler code from 0xb7eb3bb6 to 0xb7eb3bd6:
0xb7eb3bb6 <memcpy+70>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
0xb7eb3bb8 <memcpy+72>:	mov    ecx,eax
0xb7eb3bba <memcpy+74>:	rep movs BYTE PTR es:[edi],BYTE PTR ds:[esi]
0xb7eb3bbc <memcpy+76>:	pop    eax
0xb7eb3bbd <memcpy+77>:	mov    edi,eax
0xb7eb3bbf <memcpy+79>:	mov    esi,edx
0xb7eb3bc1 <memcpy+81>:	mov    eax,DWORD PTR [esp+0x4]
0xb7eb3bc5 <memcpy+85>:	ret    
0xb7eb3bc6 <memcpy+86>:	shr    ecx,1
0xb7eb3bc8 <memcpy+88>:	jae    0xb7eb3bcb <memcpy+91>
0xb7eb3bca <memcpy+90>:	movs   BYTE PTR es:[edi],BYTE PTR ds:[esi]
0xb7eb3bcb <memcpy+91>:	shr    ecx,1
0xb7eb3bcd <memcpy+93>:	jae    0xb7eb3bd1 <memcpy+97>
0xb7eb3bcf <memcpy+95>:	movs   WORD PTR es:[edi],WORD PTR ds:[esi]
0xb7eb3bd1 <memcpy+97>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
0xb7eb3bd3 <memcpy+99>:	jmp    0xb7eb3bbd <memcpy+77>
0xb7eb3bd5:	nop
End of assembler dump.
#0  memcpy () at ../sysdeps/i386/i686/memcpy.S:75
No locals.
#1  0x1fff8ab4 in ?? ()
No symbol table info available.
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
siginfo:$1 = {si_signo = 11, si_errno = 0, si_code = 1, _sifields = {_pad = {
      0, 142699928, 754, -1073744296, 142699888, 1, 142356388, 5, 142669728, 
      143433752, 0, -1, -1209320522, -1209320522, 142356388, 5, 144334716, 0, 
      -1209320522, -1073744296, 135527305, 144199376, -1209320522, 
      -1211571227, -1211571198, 0, 0, 0, 0}, _kill = {si_pid = 0, 
      si_uid = 142699928}, _timer = {si_tid = 0, si_overrun = 142699928, 
      si_sigval = {sival_int = 754, sival_ptr = 0x2f2}}, _rt = {si_pid = 0, 
      si_uid = 142699928, si_sigval = {sival_int = 754, sival_ptr = 0x2f2}}, 
    _sigchld = {si_pid = 0, si_uid = 142699928, si_status = 754, 
      si_utime = -1073744296, si_stime = 142699888}, _sigfault = {
      si_addr = 0x0}, _sigpoll = {si_band = 0, si_fd = 142699928}}}
si_addr:$2 = (void *) 0x0
A debugging session is active.

	Inferior 1 [process 20146] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
