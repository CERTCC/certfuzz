[Thread debugging using libthread_db enabled]

Program received signal SIGSEGV, Segmentation fault.
0x584e574f in ?? ()
siginfo:$1 = {si_signo = 11, si_errno = 0, si_code = 1, _sifields = {_pad = {1481529167, 
      1481529167, -1073745472, -1073745704, 0, 0, 139412332, -1073745624, 135528116, 
      1481529167, 0, -1073745672, 1481529167, 0, -1073745388, -1073745656, 
      134802072, 0, 7248, 0, 0, 7248, 1481529167, -1211595803, -1211595774, 0, 0, 0, 
      0}, _kill = {si_pid = 1481529167, si_uid = 1481529167}, _timer = {
      si_tid = 1481529167, si_overrun = 1481529167, si_sigval = {
        sival_int = -1073745472, sival_ptr = 0xbffff1c0}}, _rt = {
      si_pid = 1481529167, si_uid = 1481529167, si_sigval = {
        sival_int = -1073745472, sival_ptr = 0xbffff1c0}}, _sigchld = {
      si_pid = 1481529167, si_uid = 1481529167, si_status = -1073745472, 
      si_utime = -1073745704, si_stime = 0}, _sigfault = {si_addr = 0x584e574f}, 
    _sigpoll = {si_band = 1481529167, si_fd = 1481529167}}}
si_addr:$2 = (void *) 0x43454441
eax            0x8090d18	134810904
ecx            0x0	0
edx            0x80777f8	134707192
ebx            0xb782e6d4	-1216157996
esp            0xbffe2b4c	0xbffe2b4c
ebp            0x80777f8	0x80777f8
esi            0x1b79	7033
edi            0x1b7a	7034
eip            0x584e574f	0x584e574f
eflags         0x210286	[ PF SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
0xbffe2b4c:	0xb780ec97	0x08090d18	0x00000018	0x00000000
0xbffe2b5c:	0x080777fc	0x080915c0	0x000028f4	0xbffe2b70
0xbffe2b6c:	0x00000050	0x00001b79	0x00001b7a	0x08087a48
0xbffe2b7c:	0xb782a3b8	0x080777f8	0xb782e6d4	0x00000027
0xbffe2b8c:	0xb781749f	0x080777f8	0x080915c0	0x08085200
0xbffe2b9c:	0x080915c0	0x08085200	0x00000000	0x0808e297
0xbffe2bac:	0xb7818572	0x08090d60	0x00005f1d	0xbffe2c30
0xbffe2bbc:	0xbffe2be0	0x000000f1	0x00005002	0x00000001
0xbffe2bcc:	0x0000924f	0x01420140	0x01440143	0x01460145
0xbffe2bdc:	0x01480147	0x00000000	0x00000000	0x00000001
0xbffe2bec:	0x00000000	0x00000000	0x00000005	0x00000000
0xbffe2bfc:	0x00000000	0x00000000	0x00000000	0x00000000
0xbffe2c0c:	0x00000000	0x00000001	0x00000000	0x00000000
0xbffe2c1c:	0x00000000	0x00000000	0x00000001	0x00000000
0xbffe2c2c:	0x00000000	0x00000000	0x00000000	0x00000000
0xbffe2c3c:	0x00000000	0x0000009b	0x002cc080	0xb78170e3
process 7248
cmdline = '/usr/local/bin/exsimple'
cwd = '/home/fuzz'
exe = '/usr/local/bin/exsimple'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8060000    0x18000          0      /usr/local/bin/exsimple
	 0x8060000  0x8062000     0x2000    0x17000      /usr/local/bin/exsimple
	 0x8062000  0x8208000   0x1a6000          0           [heap]
	0xb7402000 0xb7453000    0x51000          0        
	0xb7453000 0xb7478000    0x25000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSerif-BoldItalic.ttf
	0xb7478000 0xb749d000    0x25000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSerif-Regular.ttf
	0xb749d000 0xb74bf000    0x22000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSans-Bold.ttf
	0xb74bf000 0xb74dc000    0x1d000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationMono-BoldItalic.ttf
	0xb74dc000 0xb74fb000    0x1f000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationMono-Italic.ttf
	0xb74fb000 0xb7516000    0x1b000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationMono-Regular.ttf
	0xb7516000 0xb753a000    0x24000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSerif-Bold.ttf
	0xb753a000 0xb755d000    0x23000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSans-Regular.ttf
	0xb755d000 0xb757e000    0x21000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSans-BoldItalic.ttf
	0xb757e000 0xb7598000    0x1a000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationMono-Bold.ttf
	0xb7598000 0xb75bc000    0x24000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSerif-Italic.ttf
	0xb75bc000 0xb75e4000    0x28000          0      /usr/share/fonts/truetype/ttf-liberation/LiberationSans-Italic.ttf
	0xb75e4000 0xb75f1000     0xd000          0      /usr/local/lib/libsc_ind.so
	0xb75f1000 0xb75f2000     0x1000     0xc000      /usr/local/lib/libsc_ind.so
	0xb75f2000 0xb75f9000     0x7000          0      /usr/local/lib/libsc_ca.so
	0xb75f9000 0xb75fa000     0x1000     0x6000      /usr/local/lib/libsc_ca.so
	0xb75fa000 0xb7604000     0xa000          0      /usr/local/lib/libsc_anno.so
	0xb7604000 0xb7605000     0x1000     0x9000      /usr/local/lib/libsc_anno.so
	0xb7605000 0xb7636000    0x31000          0      /usr/local/lib/libde_ss.so
	0xb7636000 0xb7637000     0x1000    0x31000      /usr/local/lib/libde_ss.so
	0xb7637000 0xb7643000     0xc000          0      /usr/local/lib/libsc_fmt.so
	0xb7643000 0xb7644000     0x1000     0xc000      /usr/local/lib/libsc_fmt.so
	0xb7644000 0xb76af000    0x6b000          0      /usr/local/lib/libsc_du.so
	0xb76af000 0xb76b1000     0x2000    0x6b000      /usr/local/lib/libsc_du.so
	0xb76b1000 0xb76b4000     0x3000          0        
	0xb76b4000 0xb7723000    0x6f000          0      /usr/local/lib/libfreetype.so.6
	0xb7723000 0xb7727000     0x4000    0x6e000      /usr/local/lib/libfreetype.so.6
	0xb7727000 0xb7740000    0x19000          0      /usr/local/lib/libwv_gdlib.so
	0xb7740000 0xb7741000     0x1000    0x19000      /usr/local/lib/libwv_gdlib.so
	0xb7741000 0xb7750000     0xf000          0      /usr/local/lib/libos_gd.so
	0xb7750000 0xb7751000     0x1000     0xf000      /usr/local/lib/libos_gd.so
	0xb7751000 0xb77c2000    0x71000          0      /usr/local/lib/libsc_img.so
	0xb77c2000 0xb77c6000     0x4000    0x70000      /usr/local/lib/libsc_img.so
	0xb77c6000 0xb780d000    0x47000          0        
	0xb780d000 0xb782e000    0x21000          0      /usr/local/lib/libvs_wk6.so
	0xb782e000 0xb782f000     0x1000    0x20000      /usr/local/lib/libvs_wk6.so
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
	0xb7fd8000 0xb7fdd000     0x5000          0      /usr/local/lib/liboc_emul.so
	0xb7fdd000 0xb7fde000     0x1000     0x4000      /usr/local/lib/liboc_emul.so
	0xb7fde000 0xb7fdf000     0x1000          0      /usr/local/lib/libex_img.so
	0xb7fdf000 0xb7fe0000     0x1000     0x1000      /usr/local/lib/libex_img.so
	0xb7fe0000 0xb7fe2000     0x2000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0      /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000      /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000      /lib/ld-2.11.2.so
	0xbffdd000 0xc0000000    0x23000          0           [stack]
