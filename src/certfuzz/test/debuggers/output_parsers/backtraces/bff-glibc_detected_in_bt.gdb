[Thread debugging using libthread_db enabled]

Program received signal SIGABRT, Aborted.
0xb7fe2424 in __kernel_vsyscall ()
process 29442
cmdline = '/usr/local/bin/ffmpeg'
cwd = '/home/fuzz'
exe = '/usr/local/bin/ffmpeg'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x87eb000   0x7a3000          0      /usr/local/bin/ffmpeg
	 0x87eb000  0x8802000    0x17000   0x7a3000      /usr/local/bin/ffmpeg
	 0x8802000  0x8d83000   0x581000          0           [heap]
	0xb7d00000 0xb7d21000    0x21000          0        
	0xb7d21000 0xb7e00000    0xdf000          0        
	0xb7e1e000 0xb7e3b000    0x1d000          0      /lib/libgcc_s.so.1
	0xb7e3b000 0xb7e3c000     0x1000    0x1c000      /lib/libgcc_s.so.1
	0xb7e3c000 0xb7e3d000     0x1000          0        
	0xb7e3d000 0xb7f7d000   0x140000          0      /lib/i686/cmov/libc-2.11.2.so
	0xb7f7d000 0xb7f7e000     0x1000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7f7e000 0xb7f80000     0x2000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7f80000 0xb7f81000     0x1000   0x142000      /lib/i686/cmov/libc-2.11.2.so
	0xb7f81000 0xb7f84000     0x3000          0        
	0xb7f84000 0xb7f99000    0x15000          0      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7f99000 0xb7f9a000     0x1000    0x14000      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7f9a000 0xb7f9b000     0x1000    0x15000      /lib/i686/cmov/libpthread-2.11.2.so
	0xb7f9b000 0xb7f9e000     0x3000          0        
	0xb7f9e000 0xb7fb1000    0x13000          0      /usr/lib/libz.so.1.2.3.4
	0xb7fb1000 0xb7fb2000     0x1000    0x13000      /usr/lib/libz.so.1.2.3.4
	0xb7fb2000 0xb7fd6000    0x24000          0      /lib/i686/cmov/libm-2.11.2.so
	0xb7fd6000 0xb7fd7000     0x1000    0x23000      /lib/i686/cmov/libm-2.11.2.so
	0xb7fd7000 0xb7fd8000     0x1000    0x24000      /lib/i686/cmov/libm-2.11.2.so
	0xb7fe0000 0xb7fe2000     0x2000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0      /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000      /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000      /lib/ld-2.11.2.so
	0xbffeb000 0xc0000000    0x15000          0           [stack]
eax            0x0	0
ecx            0x7302	29442
edx            0x6	6
ebx            0x7302	29442
esp            0xbfffed48	0xbfffed48
ebp            0xbfffed60	0xbfffed60
esi            0x0	0
edi            0xb7f7fff4	-1208483852
eip            0xb7fe2424	0xb7fe2424 <__kernel_vsyscall+16>
eflags         0x202	[ IF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
Dump of assembler code from 0xb7fe2404 to 0xb7fe2424:
0xb7fe2404 <__kernel_sigreturn+4>:	add    BYTE PTR [eax],al
0xb7fe2406 <__kernel_sigreturn+6>:	int    0x80
0xb7fe2408 <__kernel_sigreturn+8>:	nop
0xb7fe2409:	lea    esi,[esi+0x0]
0xb7fe240c <__kernel_rt_sigreturn+0>:	mov    eax,0xad
0xb7fe2411 <__kernel_rt_sigreturn+5>:	int    0x80
0xb7fe2413 <__kernel_rt_sigreturn+7>:	nop
0xb7fe2414 <__kernel_vsyscall+0>:	push   ecx
0xb7fe2415 <__kernel_vsyscall+1>:	push   edx
0xb7fe2416 <__kernel_vsyscall+2>:	push   ebp
0xb7fe2417 <__kernel_vsyscall+3>:	mov    ebp,esp
0xb7fe2419 <__kernel_vsyscall+5>:	sysenter 
0xb7fe241b <__kernel_vsyscall+7>:	nop
0xb7fe241c <__kernel_vsyscall+8>:	nop
0xb7fe241d <__kernel_vsyscall+9>:	nop
0xb7fe241e <__kernel_vsyscall+10>:	nop
0xb7fe241f <__kernel_vsyscall+11>:	nop
0xb7fe2420 <__kernel_vsyscall+12>:	nop
0xb7fe2421 <__kernel_vsyscall+13>:	nop
0xb7fe2422 <__kernel_vsyscall+14>:	jmp    0xb7fe2417 <__kernel_vsyscall+3>
End of assembler dump.
Dump of assembler code from 0xb7fe2424 to 0xb7fe2444:
0xb7fe2424 <__kernel_vsyscall+16>:	pop    ebp
0xb7fe2425 <__kernel_vsyscall+17>:	pop    edx
0xb7fe2426 <__kernel_vsyscall+18>:	pop    ecx
0xb7fe2427 <__kernel_vsyscall+19>:	ret    
0xb7fe2428:	add    BYTE PTR [esi],ch
0xb7fe242a:	jae    0xb7fe2494
0xb7fe242c:	jae    0xb7fe24a2
0xb7fe242e:	jb     0xb7fe24a4
0xb7fe2430:	popa   
0xb7fe2431:	bound  eax,QWORD PTR [eax]
0xb7fe2433:	cs
0xb7fe2434:	push   0x687361
0xb7fe2439:	cs
0xb7fe243a:	fs
0xb7fe243b:	jns    0xb7fe24ab
0xb7fe243d:	jae    0xb7fe24b8
0xb7fe243f:	ins    DWORD PTR es:[edi],dx
0xb7fe2440:	add    BYTE PTR [esi],ch
0xb7fe2442:	fs
0xb7fe2443:	jns    0xb7fe24b3
End of assembler dump.
#0  0xb7fe2424 in __kernel_vsyscall ()
No symbol table info available.
#1  0xb7e67751 in *__GI_raise (sig=6)
    at ../nptl/sysdeps/unix/sysv/linux/raise.c:64
        resultvar = <value optimized out>
        pid = -1208483852
        selftid = 29442
#2  0xb7e6ab82 in *__GI_abort () at abort.c:92
        act = {__sigaction_handler = {
            sa_handler = 0xb7fff4e4 <_rtld_local+1220>, 
            sa_sigaction = 0xb7fff4e4 <_rtld_local+1220>}, sa_mask = {__val = {
              0, 134523748, 134517316, 3221220984, 1666, 3221220952, 
              134514404, 134514328, 3221220796, 4, 3221220880, 3085964219, 
              134523748, 3085406964, 3086483444, 4, 3221222340, 3221221000, 
              3086082372, 152, 3221220880, 4, 0, 3221220976, 3221220988, 2, 
              3086350282, 3086350278, 3086345828, 3086345854, 109, 
              3221220880}}, sa_flags = -1073746344, sa_restorer = 0xb7f60b5b}
        sigs = {__val = {32, 0 <repeats 31 times>}}
#3  0xb7e9e22d in __libc_message (do_abort=2, 
    fmt=0xb7f62998 "*** glibc detected *** %s: %s: 0x%s ***\n")
    at ../sysdeps/unix/sysv/linux/libc_fatal.c:189
        ap = <value optimized out>
        fd = -1073745984
        on_2 = <value optimized out>
        list = <value optimized out>
        nlist = <value optimized out>
        cp = <value optimized out>
        written = false
#4  0xb7ea8321 in malloc_printerr (action=<value optimized out>, 
    str=0x6 <Address 0x6 out of bounds>, ptr=0x8d6e030) at malloc.c:6267
        buf = "08d6e030"
        cp = <value optimized out>
#5  0xb7ea9bd1 in _int_free (av=<value optimized out>, p=0x8d6c820)
    at malloc.c:4957
        size = 6160
        nextchunk = 0x7302
        nextsize = 40
        prevsize = <value optimized out>
        bck = <value optimized out>
        fwd = <value optimized out>
        errstr = <value optimized out>
        __func__ = "_int_free"
#6  0xb7eacc5d in *__GI___libc_free (mem=0x8d6d030) at malloc.c:3739
        ar_ptr = 0xb7f813a0
        p = 0x6
#7  0x086a8de2 in av_free (arg=0x8d6b894) at libavutil/mem.c:152
No locals.
#8  av_freep (arg=0x8d6b894) at libavutil/mem.c:159
No locals.
#9  0x0805be48 in ff_mjpeg_decode_end (avctx=0x8d6aae0)
    at libavcodec/mjpegdec.c:1572
        s = 0x8d6b660
        j = 2
#10 0x08069700 in avcodec_close (avctx=0x8d6aae0) at libavcodec/utils.c:884
No locals.
#11 0x08150468 in avformat_find_stream_info (ic=0x8d683a0, options=0x8d6b640)
    at libavformat/utils.c:2471
        i = 0
        count = 2
        ret = 25
        read_size = 3808
        j = <value optimized out>
        st = <value optimized out>
        pkt1 = {pts = 40, dts = 40, data = 0x8d78a20 "", size = 1920, 
          stream_index = 0, flags = 1, side_data = 0x0, side_data_elems = 0, 
          duration = 40, destruct = 0x817b290 <av_destruct_packet>, 
          priv = 0x0, pos = 2739, convergence_duration = 0}
        pkt = 0x19
        old_offset = 835
        orig_nb_streams = 1
        __PRETTY_FUNCTION__ = "avformat_find_stream_info"
#12 0x0807fc74 in opt_input_file (opt=0xbffffda9 "i", 
    filename=0xbffffdab "/home/fuzz/fuzzing/tmp/bff-crasher-hFxr51/sf_675d9d4d69a3eb91531ffff988a294d3-86470.mov") at ffmpeg.c:3418
        ic = 0x8d683a0
        file_iformat = <value optimized out>
        err = <value optimized out>
        i = <value optimized out>
        ret = <value optimized out>
        rfps = <value optimized out>
        rfps_base = 1
        timestamp = <value optimized out>
        buf = "(\326\371\267<\225\004\b\000\000\000\000\001\000\000\000\370\370\377\267\071\226\004\b\001\000\000\000\020\372\377\277\004\000\000\000\020\000\000\000\000\071\326\b<\372\377\277\204\031䷸\322\371\267(\372\377\277\377\377\377\377\364\357\377\267<\225\004\b\001\000\000\000@\372\377\277\266\006\377\267\260\372\377\267(\326\371\267\001\000\000\000\001\000\000\000\000\000\000\000\001\000\000\000D\222\004\bl\263~\b\000\000\000\000\204\031䷦\375\377\277"
        opts = 0x0
#13 0x080894c3 in parse_options (argc=9, argv=0xbffffc34, options=0x86b58a0, 
    parse_arg_function=0x807efe0 <opt_output_file>) at cmdutils.c:274
        bool_val = 1
        opt = <value optimized out>
        arg = 0xbffffdab "/home/fuzz/fuzzing/tmp/bff-crasher-hFxr51/sf_675d9d4d69a3eb91531ffff988a294d3-86470.mov"
        optindex = 4
        handleoptions = <value optimized out>
        po = 0x86b59b8
#14 0x080864f9 in main (argc=9, argv=0xbffffc34) at ffmpeg.c:4581
No locals.
siginfo:$1 = {si_signo = 6, si_errno = 0, si_code = -6, _sifields = {_pad = {
      29442, 1000, 0, 3, -567479296, 134, -1047969696, 146, -1044366712, 
      -1053210112, -567479296, -1055702254, -549117272, -549117272, 
      -876373352, -1056176973, -679430336, -543178848, -543178856, 
      -1056722638, 0, -1056721846, 1, 0, -1208483852, -543186944, -1056721132, 
      32, 0}, _kill = {si_pid = 29442, si_uid = 1000}, _timer = {
      si_tid = 29442, si_overrun = 1000, si_sigval = {sival_int = 0, 
        sival_ptr = 0x0}}, _rt = {si_pid = 29442, si_uid = 1000, si_sigval = {
        sival_int = 0, sival_ptr = 0x0}}, _sigchld = {si_pid = 29442, 
      si_uid = 1000, si_status = 0, si_utime = 3, si_stime = -567479296}, 
    _sigfault = {si_addr = 0x7302}, _sigpoll = {si_band = 29442, 
      si_fd = 1000}}}
si_addr:$2 = (void *) 0x7302
A debugging session is active.

	Inferior 1 [process 29442] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
 