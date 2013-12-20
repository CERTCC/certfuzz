(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
[Thread debugging using libthread_db enabled]
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
[New Thread 0xb7095750 (LWP 8519)]
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
[New Thread 0xb5e51b90 (LWP 8525)]
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)
(no debugging symbols found)

Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0xb7095750 (LWP 8519)]
0x08624849 in ?? ()
#0  0x08624849 in ?? ()
No symbol table info available.
#1  0x0862599e in ?? ()
No symbol table info available.
#2  0x08628111 in ?? ()
No symbol table info available.
#3  0x08628431 in ?? ()
No symbol table info available.
#4  0x08577d5a in ?? ()
No symbol table info available.
#5  0x080a89bd in ?? ()
No symbol table info available.
#6  0x0835822b in ?? ()
No symbol table info available.
#7  0x0835860a in ?? ()
No symbol table info available.
#8  0x083589f3 in ?? ()
No symbol table info available.
#9  0x0835a47c in ?? ()
No symbol table info available.
#10 0x0835b049 in ?? ()
No symbol table info available.
#11 0x0835b81f in ?? ()
No symbol table info available.
#12 0x08415a96 in ?? ()
No symbol table info available.
#13 0x0805cc40 in ?? ()
No symbol table info available.
#14 0x08067189 in ?? ()
No symbol table info available.
#15 0x083a004a in ?? ()
No symbol table info available.
#16 0x083a76ee in ?? ()
No symbol table info available.
#17 0x080536e3 in ?? ()
No symbol table info available.
#18 0x08055b3e in ?? ()
No symbol table info available.
#19 0x0805471d in ?? ()
No symbol table info available.
#20 0xb7a4f526 in ?? () from /usr/lib/libgtk-x11-2.0.so.0
No symbol table info available.
#21 0xb7758c7b in g_closure_invoke () from /usr/lib/libgobject-2.0.so.0
No symbol table info available.
#22 0xb776ee57 in ?? () from /usr/lib/libgobject-2.0.so.0
No symbol table info available.
#23 0xb777034f in g_signal_emit_valist () from /usr/lib/libgobject-2.0.so.0
No symbol table info available.
#24 0xb7770936 in g_signal_emit () from /usr/lib/libgobject-2.0.so.0
No symbol table info available.
#25 0xb7b6a2ae in ?? () from /usr/lib/libgtk-x11-2.0.so.0
No symbol table info available.
#26 0xb7a4956d in gtk_main_do_event () from /usr/lib/libgtk-x11-2.0.so.0
No symbol table info available.
#27 0xb78bce95 in ?? () from /usr/lib/libgdk-x11-2.0.so.0
No symbol table info available.
#28 0xb78bd4af in gdk_window_process_all_updates ()
   from /usr/lib/libgdk-x11-2.0.so.0
No symbol table info available.
#29 0xb79c04cf in ?? () from /usr/lib/libgtk-x11-2.0.so.0
No symbol table info available.
#30 0xb78a08fb in ?? () from /usr/lib/libgdk-x11-2.0.so.0
No symbol table info available.
#31 0xb76c4c81 in ?? () from /usr/lib/libglib-2.0.so.0
No symbol table info available.
#32 0xb76c6b88 in g_main_context_dispatch () from /usr/lib/libglib-2.0.so.0
No symbol table info available.
#33 0xb76ca0eb in ?? () from /usr/lib/libglib-2.0.so.0
No symbol table info available.
#34 0xb76ca5ba in g_main_loop_run () from /usr/lib/libglib-2.0.so.0
No symbol table info available.
#35 0xb7a497d9 in gtk_main () from /usr/lib/libgtk-x11-2.0.so.0
No symbol table info available.
#36 0x0804fa18 in ?? ()
No symbol table info available.
#37 0xb7364775 in __libc_start_main () from /lib/tls/i686/cmov/libc.so.6
No symbol table info available.
#38 0x0804f681 in ?? ()
No symbol table info available.
Dump of assembler code from 0xffffffe0 to 0x20:
End of assembler dump.
eax            0x0	0
ecx            0xbfffe808	-1073747960
edx            0x0	0
ebx            0x0	0
esp            0xbfffe5b0	0xbfffe5b0
ebp            0xbfffe648	0xbfffe648
esi            0xb620481c	-1239398372
edi            0x0	0
eip            0x8624849	0x8624849
eflags         0x10286	[ PF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
st0            0.063636363636363634092602426656215542	(raw 0x3ffb8253c8253c825279)
st1            240	(raw 0x4006f000000000000000)
st2            60	(raw 0x4004f000000000000000)
st3            282.85714285714285715078730731875112	(raw 0x40078d6db6db6db6db6e)
st4            40640.227727272724091989175576600246	(raw 0x400e9ec03a4c55a4c1db)
st5            13801	(raw 0x400cd7a4000000000000)
st6            690.04998779296875	(raw 0x4008ac83330000000000)
st7            1.5	(raw 0x3fffc000000000000000)
fctrl          0x37f	895
fstat          0x27	39
ftag           0xffff	65535
fiseg          0x0	0
fioff          0x8622b23	140651299
foseg          0x0	0
fooff          0xb60ba630	-1240750544
fop            0x518	1304
xmm0           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm1           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm2           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm3           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm4           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm5           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm6           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
xmm7           {v4_float = {0x0, 0x0, 0x0, 0x0}, v2_double = {0x0, 0x0}, 
  v16_int8 = {0x0 <repeats 16 times>}, v8_int16 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0x0, 0x0}, v4_int32 = {0x0, 0x0, 0x0, 0x0}, v2_int64 = {0x0, 0x0}, 
  uint128 = 0x00000000000000000000000000000000}
mxcsr          0x1f80	[ IM DM ZM OM UM PM ]
mm0            {uint64 = 0x8253c8253c825279, v2_int32 = {0x3c825279, 
    0x8253c825}, v4_int16 = {0x5279, 0x3c82, 0xc825, 0x8253}, v8_int8 = {0x79, 
    0x52, 0x82, 0x3c, 0x25, 0xc8, 0x53, 0x82}}
mm1            {uint64 = 0xf000000000000000, v2_int32 = {0x0, 0xf0000000}, 
  v4_int16 = {0x0, 0x0, 0x0, 0xf000}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0xf0}}
mm2            {uint64 = 0xf000000000000000, v2_int32 = {0x0, 0xf0000000}, 
  v4_int16 = {0x0, 0x0, 0x0, 0xf000}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0xf0}}
mm3            {uint64 = 0x8d6db6db6db6db6e, v2_int32 = {0x6db6db6e, 
    0x8d6db6db}, v4_int16 = {0xdb6e, 0x6db6, 0xb6db, 0x8d6d}, v8_int8 = {0x6e, 
    0xdb, 0xb6, 0x6d, 0xdb, 0xb6, 0x6d, 0x8d}}
mm4            {uint64 = 0x9ec03a4c55a4c1db, v2_int32 = {0x55a4c1db, 
    0x9ec03a4c}, v4_int16 = {0xc1db, 0x55a4, 0x3a4c, 0x9ec0}, v8_int8 = {0xdb, 
    0xc1, 0xa4, 0x55, 0x4c, 0x3a, 0xc0, 0x9e}}
mm5            {uint64 = 0xd7a4000000000000, v2_int32 = {0x0, 0xd7a40000}, 
  v4_int16 = {0x0, 0x0, 0x0, 0xd7a4}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0xa4, 0xd7}}
mm6            {uint64 = 0xac83330000000000, v2_int32 = {0x0, 0xac833300}, 
  v4_int16 = {0x0, 0x0, 0x3300, 0xac83}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 
    0x33, 0x83, 0xac}}
mm7            {uint64 = 0xc000000000000000, v2_int32 = {0x0, 0xc0000000}, 
  v4_int16 = {0x0, 0x0, 0x0, 0xc000}, v8_int8 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0xc0}}
The program is running.  Exit anyway? (y or n) [answered Y; input not from terminal]
