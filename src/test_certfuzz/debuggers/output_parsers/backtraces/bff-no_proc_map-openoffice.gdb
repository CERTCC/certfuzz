[Thread debugging using libthread_db enabled]
[New Thread 0xb4d78b70 (LWP 18823)]
[New Thread 0xb308fb70 (LWP 18824)]
[New Thread 0xb288eb70 (LWP 18825)]
[New Thread 0xafcb1b70 (LWP 18826)]
[New Thread 0xae747b70 (LWP 18830)]
[New Thread 0xab31ab70 (LWP 18831)]
[New Thread 0xab299b70 (LWP 18832)]
[New Thread 0xab248b70 (LWP 18833)]
[New Thread 0xab1f7b70 (LWP 18834)]
[New Thread 0xab1a6b70 (LWP 18835)]
[New Thread 0xab125b70 (LWP 18836)]
[New Thread 0xab0d4b70 (LWP 18837)]
[New Thread 0xaafb4b70 (LWP 18838)]
[New Thread 0xaadffb70 (LWP 18839)]

Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0xaafb4b70 (LWP 18838)]
0xab6d24ea in ?? ()
#0  0xab6d24ea in ?? ()
No symbol table info available.
#1  0xab70f690 in ?? ()
No symbol table info available.
#2  0xab711272 in ?? ()
No symbol table info available.
#3  0xab747067 in ?? ()
No symbol table info available.
#4  0xab739dda in ?? ()
No symbol table info available.
#5  0xab740016 in ?? ()
No symbol table info available.
#6  0xab723735 in ?? ()
No symbol table info available.
#7  0xab723eca in ?? ()
No symbol table info available.
#8  0xab723eca in ?? ()
No symbol table info available.
#9  0xab720861 in ?? ()
No symbol table info available.
#10 0xab71ee29 in ?? ()
No symbol table info available.
#11 0xab71af90 in ?? ()
No symbol table info available.
#12 0xab71277e in ?? ()
No symbol table info available.
#13 0xab711c03 in ?? ()
No symbol table info available.
#14 0xab657ec5 in ?? ()
No symbol table info available.
#15 0xab6584a9 in ?? ()
No symbol table info available.
#16 0xab657fcd in ?? ()
No symbol table info available.
#17 0xab65827d in ?? ()
No symbol table info available.
#18 0xab657da1 in ?? ()
No symbol table info available.
#19 0xab657da1 in ?? ()
No symbol table info available.
#20 0xab65827d in ?? ()
No symbol table info available.
#21 0xab657da1 in ?? ()
No symbol table info available.
#22 0xab657da1 in ?? ()
No symbol table info available.
#23 0xab657da1 in ?? ()
No symbol table info available.
#24 0xab657f07 in ?? ()
No symbol table info available.
#25 0xab657da1 in ?? ()
No symbol table info available.
#26 0xab657f07 in ?? ()
No symbol table info available.
#27 0xab657f07 in ?? ()
No symbol table info available.
#28 0xab6552cc in ?? ()
No symbol table info available.
#29 0xad891d65 in JavaCalls::call_helper(JavaValue*, methodHandle*, JavaCallArguments*, Thread*) ()
   from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#30 0xad981e69 in os::os_exception_wrapper(void (*)(JavaValue*, methodHandle*, JavaCallArguments*, Thread*), JavaValue*, methodHandle*, JavaCallArguments*, Thread*) () from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#31 0xad890c5f in JavaCalls::call(JavaValue*, methodHandle, JavaCallArguments*, Thread*) ()
   from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#32 0xad89113a in JavaCalls::call_virtual(JavaValue*, KlassHandle, symbolHandle, symbolHandle, JavaCallArguments*, Thread*) ()
   from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#33 0xad8912ca in JavaCalls::call_virtual(JavaValue*, Handle, KlassHandle, symbolHandle, symbolHandle, Thread*) ()
   from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#34 0xad8e3792 in thread_entry(JavaThread*, Thread*) () from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#35 0xada2c69c in JavaThread::thread_main_inner() () from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#36 0xada2c75a in JavaThread::run() () from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#37 0xad987ea1 in java_start(Thread*) () from /usr/lib/jvm/java-6-openjdk/jre/lib/i386/client/libjvm.so
No symbol table info available.
#38 0xb79f6955 in start_thread (arg=0xaafb4b70) at pthread_create.c:300
        __res = <value optimized out>
        __ignore1 = <value optimized out>
        __ignore2 = <value optimized out>
        pd = 0xaafb4b70
        now = <value optimized out>
        unwind_buf = {cancel_jmp_buf = {{jmp_buf = {-1214222348, 0, 4001536, -1426373496, 759097910, -445915124}, 
              mask_was_saved = 0}}, priv = {pad = {0x0, 0x0, 0x0, 0x0}, data = {prev = 0x0, cleanup = 0x0, canceltype = 0}}}
        not_first_call = <value optimized out>
        freesize = <value optimized out>
        __PRETTY_FUNCTION__ = "start_thread"
#39 0xb7b1810e in clone () at ../sysdeps/unix/sysv/linux/i386/clone.S:130
No locals.
Dump of assembler code from 0xab6d24ca to 0xab6d250a:
0xab6d24ca:	in     $0x5d,%eax
0xab6d24cc:	test   %eax,0xb421a100
0xab6d24d2:	ret    
0xab6d24d3:	mov    $0x1,%eax
0xab6d24d8:	mov    %ebp,%esp
0xab6d24da:	pop    %ebp
0xab6d24db:	test   %eax,0xb421a100
0xab6d24e1:	ret    
0xab6d24e2:	mov    $0x0,%eax
0xab6d24e7:	mov    %ebp,%esp
0xab6d24e9:	pop    %ebp
0xab6d24ea:	test   %eax,0xb421a100
0xab6d24f0:	ret    
0xab6d24f1:	mov    $0x1,%eax
0xab6d24f6:	mov    %ebp,%esp
0xab6d24f8:	pop    %ebp
0xab6d24f9:	test   %eax,0xb421a100
0xab6d24ff:	ret    
0xab6d2500:	mov    %edx,(%esp)
0xab6d2503:	call   0xab6cb160
0xab6d2508:	call   0xab6c9be0
End of assembler dump.
eax            0x0	0
ecx            0x94774970	-1804121744
edx            0x8f944be8	-1886106648
ebx            0x8f832d30	-1887228624
esp            0xaafb346c	0xaafb346c
ebp            0xaafb3488	0xaafb3488
esi            0x0	0
edi            0x26	38
eip            0xab6d24ea	0xab6d24ea
eflags         0x210293	[ CF AF SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
st0            0	(raw 0x00000000000000000000)
st1            0	(raw 0x00000000000000000000)
st2            0	(raw 0x00000000000000000000)
st3            0	(raw 0x00000000000000000000)
st4            100	(raw 0x4005c800000000000000)
st5            100.003755092620849609375	(raw 0x4005c801ec3000000000)
st6            -2147483648	(raw 0xc01e8000000000000000)
st7            48	(raw 0x4004c000000000000000)
fctrl          0x27f	639
fstat          0x120	288
ftag           0xffff	65535
fiseg          0x0	0
fioff          0xad9c763c	-1382255044
foseg          0x0	0
fooff          0xaafb3790	-1426376816
fop            0x35d	861
xmm0           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0, 0x0, 0x40, 0x3f, 
    0x0 <repeats 12 times>}, v8_int16 = {0x0, 0x3f40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x3f400000, 0x0, 0x0, 0x0}, 
  v2_int64 = {0x3f400000, 0x0}, uint128 = 0x0000000000000000000000003f400000}
xmm1           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm2           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm3           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm4           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm5           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm6           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm7           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
mxcsr          0x1f80	[ IM DM ZM OM UM PM ]
mm0            {uint64 = 0x0, v2_int32 = {0x0, 0x0}, v4_int16 = {0x0, 0x0, 0x0, 0x0}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0}}
mm1            {uint64 = 0x0, v2_int32 = {0x0, 0x0}, v4_int16 = {0x0, 0x0, 0x0, 0x0}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0}}
mm2            {uint64 = 0x0, v2_int32 = {0x0, 0x0}, v4_int16 = {0x0, 0x0, 0x0, 0x0}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0}}
mm3            {uint64 = 0x0, v2_int32 = {0x0, 0x0}, v4_int16 = {0x0, 0x0, 0x0, 0x0}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0}}
mm4            {uint64 = 0xc800000000000000, v2_int32 = {0x0, 0xc8000000}, v4_int16 = {0x0, 0x0, 0x0, 0xc800}, v8_int8 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc8}}
mm5            {uint64 = 0xc801ec3000000000, v2_int32 = {0x0, 0xc801ec30}, v4_int16 = {0x0, 0x0, 0xec30, 0xc801}, v8_int8 = {
    0x0, 0x0, 0x0, 0x0, 0x30, 0xec, 0x1, 0xc8}}
mm6            {uint64 = 0x8000000000000000, v2_int32 = {0x0, 0x80000000}, v4_int16 = {0x0, 0x0, 0x0, 0x8000}, v8_int8 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80}}
mm7            {uint64 = 0xc000000000000000, v2_int32 = {0x0, 0xc0000000}, v4_int16 = {0x0, 0x0, 0x0, 0xc000}, v8_int8 = {0x0, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0}}
A debugging session is active.

	Inferior 1 [process 18820] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
