
Program received signal SIGSEGV, Segmentation fault.
0xb77dd58a in latch_quant_tables (cinfo=0x8136784) at jdinput.c:240
	in jdinput.c
process 3099
cmdline = '/usr/bin/xpdf'
cwd = '/home/fuzz'
exe = '/usr/bin/xpdf'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8080000    0x38000          0      /usr/bin/xpdf
	 0x8080000  0x8084000     0x4000    0x37000      /usr/bin/xpdf
	 0x8084000  0x814f000    0xcb000          0           [heap]
	0xb72cb000 0xb75c9000   0x2fe000          0        
	0xb75c9000 0xb75cd000     0x4000          0      /usr/lib/libXfixes.so.3.1.0
	0xb75cd000 0xb75ce000     0x1000     0x3000      /usr/lib/libXfixes.so.3.1.0
	0xb75ce000 0xb75d6000     0x8000          0      /usr/lib/libXrender.so.1.3.0
	0xb75d6000 0xb75d7000     0x1000     0x7000      /usr/lib/libXrender.so.1.3.0
	0xb75d7000 0xb75df000     0x8000          0      /usr/lib/libXcursor.so.1.0.2
	0xb75df000 0xb75e0000     0x1000     0x7000      /usr/lib/libXcursor.so.1.0.2
	0xb75e0000 0xb75e2000     0x2000          0        
	0xb75e2000 0xb75e6000     0x4000          0      /usr/lib/libXdmcp.so.6.0.0
	0xb75e6000 0xb75e7000     0x1000     0x3000      /usr/lib/libXdmcp.so.6.0.0
	0xb75e7000 0xb760b000    0x24000          0      /usr/lib/libexpat.so.1.5.2
	0xb760b000 0xb760d000     0x2000    0x23000      /usr/lib/libexpat.so.1.5.2
	0xb760d000 0xb760e000     0x1000          0        
	0xb760e000 0xb7610000     0x2000          0      /usr/lib/libXau.so.6.0.0
	0xb7610000 0xb7611000     0x1000     0x1000      /usr/lib/libXau.so.6.0.0
	0xb7611000 0xb7614000     0x3000          0      /lib/libuuid.so.1.3.0
	0xb7614000 0xb7615000     0x1000     0x2000      /lib/libuuid.so.1.3.0
	0xb7615000 0xb7617000     0x2000          0      /lib/i686/cmov/libdl-2.11.2.so
	0xb7617000 0xb7618000     0x1000     0x1000      /lib/i686/cmov/libdl-2.11.2.so
	0xb7618000 0xb7619000     0x1000     0x2000      /lib/i686/cmov/libdl-2.11.2.so
	0xb7619000 0xb7631000    0x18000          0      /usr/lib/libxcb.so.1.1.0
	0xb7631000 0xb7632000     0x1000    0x17000      /usr/lib/libxcb.so.1.1.0
	0xb7632000 0xb765f000    0x2d000          0      /usr/lib/libfontconfig.so.1.4.4
	0xb765f000 0xb7661000     0x2000    0x2c000      /usr/lib/libfontconfig.so.1.4.4
	0xb7661000 0xb7662000     0x1000          0        
	0xb7662000 0xb7786000   0x124000          0      /usr/lib/libxml2.so.2.7.8
	0xb7786000 0xb778b000     0x5000   0x124000      /usr/lib/libxml2.so.2.7.8
	0xb778b000 0xb778c000     0x1000          0        
	0xb778c000 0xb77a8000    0x1c000          0      /usr/lib/libopenjpeg-2.1.3.0.so
	0xb77a8000 0xb77a9000     0x1000    0x1c000      /usr/lib/libopenjpeg-2.1.3.0.so
	0xb77a9000 0xb77cc000    0x23000          0      /lib/libpng12.so.0.44.0
	0xb77cc000 0xb77cd000     0x1000    0x22000      /lib/libpng12.so.0.44.0
	0xb77cd000 0xb77ec000    0x1f000          0      /usr/lib/libjpeg.so.62.0.0
	0xb77ec000 0xb77ed000     0x1000    0x1e000      /usr/lib/libjpeg.so.62.0.0
	0xb77ed000 0xb781d000    0x30000          0      /usr/lib/liblcms.so.1.0.18
	0xb781d000 0xb781f000     0x2000    0x2f000      /usr/lib/liblcms.so.1.0.18
	0xb781f000 0xb7821000     0x2000          0        
	0xb7821000 0xb7834000    0x13000          0      /usr/lib/libz.so.1.2.3.4
	0xb7834000 0xb7835000     0x1000    0x13000      /usr/lib/libz.so.1.2.3.4
	0xb7835000 0xb7836000     0x1000          0        
	0xb7836000 0xb78a9000    0x73000          0      /usr/lib/libfreetype.so.6.6.0
	0xb78a9000 0xb78ad000     0x4000    0x73000      /usr/lib/libfreetype.so.6.6.0
	0xb78ad000 0xb78bb000     0xe000          0      /usr/lib/libXext.so.6.4.0
	0xb78bb000 0xb78bc000     0x1000     0xd000      /usr/lib/libXext.so.6.4.0
	0xb78bc000 0xb78c3000     0x7000          0      /usr/lib/libXp.so.6.2.0
	0xb78c3000 0xb78c4000     0x1000     0x6000      /usr/lib/libXp.so.6.2.0
	0xb78c4000 0xb78d8000    0x14000          0      /usr/lib/libICE.so.6.3.0
	0xb78d8000 0xb78da000     0x2000    0x13000      /usr/lib/libICE.so.6.3.0
	0xb78da000 0xb78db000     0x1000          0        
	0xb78db000 0xb78e2000     0x7000          0      /usr/lib/libSM.so.6.0.1
	0xb78e2000 0xb78e3000     0x1000     0x6000      /usr/lib/libSM.so.6.0.1
	0xb78e3000 0xb78e4000     0x1000          0        
	0xb78e4000 0xb79fd000   0x119000          0      /usr/lib/libX11.so.6.3.0
	0xb79fd000 0xb7a01000     0x4000   0x118000      /usr/lib/libX11.so.6.3.0
	0xb7a01000 0xb7a4f000    0x4e000          0      /usr/lib/libXt.so.6.0.0
	0xb7a4f000 0xb7a53000     0x4000    0x4d000      /usr/lib/libXt.so.6.0.0
	0xb7a53000 0xb7b93000   0x140000          0      /lib/i686/cmov/libc-2.11.2.so
	0xb7b93000 0xb7b95000     0x2000   0x13f000      /lib/i686/cmov/libc-2.11.2.so
	0xb7b95000 0xb7b96000     0x1000   0x141000      /lib/i686/cmov/libc-2.11.2.so
	0xb7b96000 0xb7b99000     0x3000          0        
	0xb7b99000 0xb7bb6000    0x1d000          0      /lib/libgcc_s.so.1
	0xb7bb6000 0xb7bb7000     0x1000    0x1c000      /lib/libgcc_s.so.1
	0xb7bb7000 0xb7bdb000    0x24000          0      /lib/i686/cmov/libm-2.11.2.so
	0xb7bdb000 0xb7bdc000     0x1000    0x23000      /lib/i686/cmov/libm-2.11.2.so
	0xb7bdc000 0xb7bdd000     0x1000    0x24000      /lib/i686/cmov/libm-2.11.2.so
	0xb7bdd000 0xb7cc6000    0xe9000          0      /usr/lib/libstdc++.so.6.0.13
	0xb7cc6000 0xb7cca000     0x4000    0xe9000      /usr/lib/libstdc++.so.6.0.13
	0xb7cca000 0xb7ccb000     0x1000    0xed000      /usr/lib/libstdc++.so.6.0.13
	0xb7ccb000 0xb7cd3000     0x8000          0        
	0xb7cd3000 0xb7e78000   0x1a5000          0      /usr/lib/libpoppler.so.5.0.0
	0xb7e78000 0xb7e96000    0x1e000   0x1a5000      /usr/lib/libpoppler.so.5.0.0
	0xb7e96000 0xb7fc5000   0x12f000          0      /usr/lib/libXm.so.2.0.1
	0xb7fc5000 0xb7fd7000    0x12000   0x12e000      /usr/lib/libXm.so.2.0.1
	0xb7fd7000 0xb7fd9000     0x2000          0        
	0xb7fdf000 0xb7fe2000     0x3000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0      /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000      /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000      /lib/ld-2.11.2.so
	0xbffeb000 0xc0000000    0x15000          0           [stack]
eax            0x813a91c	135506204
ecx            0x21	33
edx            0x1f50	8016
ebx            0xb77ecd34	-1216426700
esp            0xbffff160	0xbffff160
ebp            0xbffff198	0xbffff198
esi            0x0	0
edi            0x813a91c	135506204
eip            0xb77dd58a	0xb77dd58a <start_input_pass+506>
eflags         0x10282	[ SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
Dump of assembler code for function start_input_pass:
   0xb77dd390 <+0>:	push   ebp
   0xb77dd391 <+1>:	mov    ebp,esp
   0xb77dd393 <+3>:	push   edi
   0xb77dd394 <+4>:	push   esi
   0xb77dd395 <+5>:	push   ebx
   0xb77dd396 <+6>:	sub    esp,0x2c
   0xb77dd399 <+9>:	mov    edx,DWORD PTR [ebp+0x8]
   0xb77dd39c <+12>:	call   0xb77cf7c7 <__i686.get_pc_thunk.bx>
   0xb77dd3a1 <+17>:	add    ebx,0xf993
   0xb77dd3a7 <+23>:	mov    eax,DWORD PTR [edx+0x148]
   0xb77dd3ad <+29>:	cmp    eax,0x1
   0xb77dd3b0 <+32>:	je     0xb77dd5b8 <start_input_pass+552>
   0xb77dd3b6 <+38>:	sub    eax,0x1
   0xb77dd3b9 <+41>:	cmp    eax,0x3
   0xb77dd3bc <+44>:	ja     0xb77dd625 <start_input_pass+661>
   0xb77dd3c2 <+50>:	mov    edx,DWORD PTR [ebp+0x8]
   0xb77dd3c5 <+53>:	mov    eax,DWORD PTR [edx+0x134]
   0xb77dd3cb <+59>:	shl    eax,0x3
   0xb77dd3ce <+62>:	mov    DWORD PTR [esp+0x4],eax
   0xb77dd3d2 <+66>:	mov    eax,DWORD PTR [edx+0x1c]
   0xb77dd3d5 <+69>:	mov    DWORD PTR [esp],eax
   0xb77dd3d8 <+72>:	call   0xb77cf534 <jdiv_round_up@plt>
   0xb77dd3dd <+77>:	mov    ecx,DWORD PTR [ebp+0x8]
   0xb77dd3e0 <+80>:	mov    DWORD PTR [ecx+0x15c],eax
   0xb77dd3e6 <+86>:	mov    eax,DWORD PTR [ecx+0x138]
   0xb77dd3ec <+92>:	shl    eax,0x3
   0xb77dd3ef <+95>:	mov    DWORD PTR [esp+0x4],eax
   0xb77dd3f3 <+99>:	mov    eax,DWORD PTR [ecx+0x20]
   0xb77dd3f6 <+102>:	mov    DWORD PTR [esp],eax
   0xb77dd3f9 <+105>:	call   0xb77cf534 <jdiv_round_up@plt>
   0xb77dd3fe <+110>:	mov    edi,DWORD PTR [ebp+0x8]
   0xb77dd401 <+113>:	mov    DWORD PTR [edi+0x164],0x0
   0xb77dd40b <+123>:	mov    DWORD PTR [edi+0x160],eax
   0xb77dd411 <+129>:	mov    edi,DWORD PTR [edi+0x148]
   0xb77dd417 <+135>:	test   edi,edi
   0xb77dd419 <+137>:	jle    0xb77dd4f3 <start_input_pass+355>
   0xb77dd41f <+143>:	xor    esi,esi
   0xb77dd421 <+145>:	mov    eax,DWORD PTR [ebp+0x8]
   0xb77dd424 <+148>:	mov    ecx,DWORD PTR [eax+esi*4+0x14c]
   0xb77dd42b <+155>:	mov    edx,DWORD PTR [ecx+0x8]
   0xb77dd42e <+158>:	mov    eax,DWORD PTR [ecx+0x24]
   0xb77dd431 <+161>:	mov    edi,DWORD PTR [ecx+0xc]
   0xb77dd434 <+164>:	mov    DWORD PTR [ebp-0x1c],edx
   0xb77dd437 <+167>:	imul   eax,edx
   0xb77dd43a <+170>:	mov    DWORD PTR [ecx+0x34],edx
   0xb77dd43d <+173>:	mov    DWORD PTR [ebp-0x20],edi
   0xb77dd440 <+176>:	mov    DWORD PTR [ecx+0x38],edi
   0xb77dd443 <+179>:	imul   edi,edx
   0xb77dd446 <+182>:	xor    edx,edx
   0xb77dd448 <+184>:	mov    DWORD PTR [ecx+0x40],eax
   0xb77dd44b <+187>:	mov    eax,DWORD PTR [ecx+0x1c]
   0xb77dd44e <+190>:	div    DWORD PTR [ebp-0x1c]
   0xb77dd451 <+193>:	mov    DWORD PTR [ecx+0x3c],edi
   0xb77dd454 <+196>:	test   edx,edx
   0xb77dd456 <+198>:	je     0xb77dd45b <start_input_pass+203>
   0xb77dd458 <+200>:	mov    DWORD PTR [ebp-0x1c],edx
   0xb77dd45b <+203>:	mov    eax,DWORD PTR [ebp-0x1c]
   0xb77dd45e <+206>:	xor    edx,edx
   0xb77dd460 <+208>:	mov    DWORD PTR [ecx+0x44],eax
   0xb77dd463 <+211>:	mov    eax,DWORD PTR [ecx+0x20]
   0xb77dd466 <+214>:	div    DWORD PTR [ebp-0x20]
   0xb77dd469 <+217>:	test   edx,edx
   0xb77dd46b <+219>:	je     0xb77dd470 <start_input_pass+224>
   0xb77dd46d <+221>:	mov    DWORD PTR [ebp-0x20],edx
   0xb77dd470 <+224>:	mov    edx,DWORD PTR [ebp-0x20]
   0xb77dd473 <+227>:	mov    eax,edi
   0xb77dd475 <+229>:	mov    DWORD PTR [ecx+0x48],edx
   0xb77dd478 <+232>:	mov    ecx,DWORD PTR [ebp+0x8]
   0xb77dd47b <+235>:	add    eax,DWORD PTR [ecx+0x164]
   0xb77dd481 <+241>:	cmp    eax,0xa
   0xb77dd484 <+244>:	jg     0xb77dd530 <start_input_pass+416>
   0xb77dd48a <+250>:	test   edi,edi
   0xb77dd48c <+252>:	jle    0xb77dd4b7 <start_input_pass+295>
   0xb77dd48e <+254>:	mov    eax,DWORD PTR [ebp+0x8]
   0xb77dd491 <+257>:	mov    ecx,DWORD PTR [eax+0x164]
   0xb77dd497 <+263>:	lea    edx,[eax+ecx*4+0x168]
   0xb77dd49e <+270>:	xor    eax,eax
   0xb77dd4a0 <+272>:	add    eax,0x1
   0xb77dd4a3 <+275>:	mov    DWORD PTR [edx],esi
   0xb77dd4a5 <+277>:	add    edx,0x4
   0xb77dd4a8 <+280>:	cmp    eax,edi
   0xb77dd4aa <+282>:	jne    0xb77dd4a0 <start_input_pass+272>
   0xb77dd4ac <+284>:	mov    edx,DWORD PTR [ebp+0x8]
   0xb77dd4af <+287>:	add    eax,ecx
   0xb77dd4b1 <+289>:	mov    DWORD PTR [edx+0x164],eax
   0xb77dd4b7 <+295>:	mov    ecx,DWORD PTR [ebp+0x8]
   0xb77dd4ba <+298>:	add    esi,0x1
   0xb77dd4bd <+301>:	mov    eax,DWORD PTR [ecx+0x148]
   0xb77dd4c3 <+307>:	cmp    esi,eax
   0xb77dd4c5 <+309>:	jl     0xb77dd421 <start_input_pass+145>
   0xb77dd4cb <+315>:	xor    edx,edx
   0xb77dd4cd <+317>:	test   eax,eax
   0xb77dd4cf <+319>:	jle    0xb77dd4f3 <start_input_pass+355>
   0xb77dd4d1 <+321>:	mov    edi,DWORD PTR [ebp+0x8]
   0xb77dd4d4 <+324>:	mov    edi,DWORD PTR [edi+edx*4+0x14c]
   0xb77dd4db <+331>:	mov    esi,DWORD PTR [edi+0x4c]
   0xb77dd4de <+334>:	mov    DWORD PTR [ebp-0x1c],edi
   0xb77dd4e1 <+337>:	test   esi,esi
   0xb77dd4e3 <+339>:	je     0xb77dd548 <start_input_pass+440>
   0xb77dd4e5 <+341>:	mov    edi,DWORD PTR [ebp+0x8]
   0xb77dd4e8 <+344>:	add    edx,0x1
   0xb77dd4eb <+347>:	cmp    edx,DWORD PTR [edi+0x148]
   0xb77dd4f1 <+353>:	jl     0xb77dd4d1 <start_input_pass+321>
   0xb77dd4f3 <+355>:	mov    edx,DWORD PTR [ebp+0x8]
   0xb77dd4f6 <+358>:	mov    eax,DWORD PTR [edx+0x1bc]
   0xb77dd4fc <+364>:	mov    DWORD PTR [esp],edx
   0xb77dd4ff <+367>:	call   DWORD PTR [eax]
   0xb77dd501 <+369>:	mov    ecx,DWORD PTR [ebp+0x8]
   0xb77dd504 <+372>:	mov    eax,DWORD PTR [ecx+0x1ac]
   0xb77dd50a <+378>:	mov    DWORD PTR [esp],ecx
   0xb77dd50d <+381>:	call   DWORD PTR [eax]
   0xb77dd50f <+383>:	mov    edi,DWORD PTR [ebp+0x8]
   0xb77dd512 <+386>:	mov    edx,DWORD PTR [edi+0x1ac]
   0xb77dd518 <+392>:	mov    eax,DWORD PTR [edi+0x1b4]
   0xb77dd51e <+398>:	mov    edx,DWORD PTR [edx+0x4]
   0xb77dd521 <+401>:	mov    DWORD PTR [eax],edx
   0xb77dd523 <+403>:	add    esp,0x2c
   0xb77dd526 <+406>:	pop    ebx
   0xb77dd527 <+407>:	pop    esi
   0xb77dd528 <+408>:	pop    edi
   0xb77dd529 <+409>:	pop    ebp
   0xb77dd52a <+410>:	ret    
   0xb77dd52b <+411>:	nop
   0xb77dd52c <+412>:	lea    esi,[esi+eiz*1+0x0]
   0xb77dd530 <+416>:	mov    eax,DWORD PTR [ecx]
   0xb77dd532 <+418>:	mov    DWORD PTR [eax+0x14],0xd
   0xb77dd539 <+425>:	mov    DWORD PTR [esp],ecx
   0xb77dd53c <+428>:	call   DWORD PTR [eax]
   0xb77dd53e <+430>:	jmp    0xb77dd48a <start_input_pass+250>
   0xb77dd543 <+435>:	nop
   0xb77dd544 <+436>:	lea    esi,[esi+eiz*1+0x0]
   0xb77dd548 <+440>:	mov    eax,DWORD PTR [edi+0x10]
   0xb77dd54b <+443>:	cmp    eax,0x3
   0xb77dd54e <+446>:	lea    esi,[eax+0x28]
   0xb77dd551 <+449>:	ja     0xb77dd59a <start_input_pass+522>
   0xb77dd553 <+451>:	mov    ecx,DWORD PTR [ebp+0x8]
   0xb77dd556 <+454>:	mov    ecx,DWORD PTR [ecx+esi*4+0x4]
   0xb77dd55a <+458>:	test   ecx,ecx
   0xb77dd55c <+460>:	je     0xb77dd59a <start_input_pass+522>
   0xb77dd55e <+462>:	mov    ecx,DWORD PTR [ebp+0x8]
   0xb77dd561 <+465>:	mov    DWORD PTR [ebp-0x24],edx
   0xb77dd564 <+468>:	mov    eax,DWORD PTR [ecx+0x4]
   0xb77dd567 <+471>:	mov    DWORD PTR [esp],ecx
   0xb77dd56a <+474>:	mov    DWORD PTR [esp+0x8],0x84
   0xb77dd572 <+482>:	mov    DWORD PTR [esp+0x4],0x1
   0xb77dd57a <+490>:	call   DWORD PTR [eax]
   0xb77dd57c <+492>:	mov    edi,DWORD PTR [ebp+0x8]
   0xb77dd57f <+495>:	mov    ecx,0x21
   0xb77dd584 <+500>:	mov    esi,DWORD PTR [edi+esi*4+0x4]
   0xb77dd588 <+504>:	mov    edi,eax
=> 0xb77dd58a <+506>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
   0xb77dd58c <+508>:	mov    ecx,DWORD PTR [ebp-0x1c]
   0xb77dd58f <+511>:	mov    edx,DWORD PTR [ebp-0x24]
   0xb77dd592 <+514>:	mov    DWORD PTR [ecx+0x4c],eax
   0xb77dd595 <+517>:	jmp    0xb77dd4e5 <start_input_pass+341>
   0xb77dd59a <+522>:	mov    edi,DWORD PTR [ebp+0x8]
   0xb77dd59d <+525>:	mov    ecx,DWORD PTR [edi]
   0xb77dd59f <+527>:	mov    DWORD PTR [ecx+0x18],eax
   0xb77dd5a2 <+530>:	mov    eax,DWORD PTR [edi]
   0xb77dd5a4 <+532>:	mov    DWORD PTR [ecx+0x14],0x34
   0xb77dd5ab <+539>:	mov    DWORD PTR [ebp-0x24],edx
   0xb77dd5ae <+542>:	mov    DWORD PTR [esp],edi
   0xb77dd5b1 <+545>:	call   DWORD PTR [eax]
   0xb77dd5b3 <+547>:	mov    edx,DWORD PTR [ebp-0x24]
   0xb77dd5b6 <+550>:	jmp    0xb77dd55e <start_input_pass+462>
   0xb77dd5b8 <+552>:	mov    ecx,DWORD PTR [edx+0x14c]
   0xb77dd5be <+558>:	mov    eax,DWORD PTR [ecx+0x1c]
   0xb77dd5c1 <+561>:	mov    DWORD PTR [edx+0x15c],eax
   0xb77dd5c7 <+567>:	mov    eax,DWORD PTR [ecx+0x20]
   0xb77dd5ca <+570>:	mov    DWORD PTR [edx+0x160],eax
   0xb77dd5d0 <+576>:	mov    eax,DWORD PTR [ecx+0x24]
   0xb77dd5d3 <+579>:	xor    edx,edx
   0xb77dd5d5 <+581>:	mov    esi,DWORD PTR [ecx+0xc]
   0xb77dd5d8 <+584>:	mov    DWORD PTR [ecx+0x34],0x1
   0xb77dd5df <+591>:	mov    DWORD PTR [ecx+0x38],0x1
   0xb77dd5e6 <+598>:	mov    DWORD PTR [ecx+0x40],eax
   0xb77dd5e9 <+601>:	mov    eax,DWORD PTR [ecx+0x20]
   0xb77dd5ec <+604>:	mov    DWORD PTR [ecx+0x3c],0x1
   0xb77dd5f3 <+611>:	mov    DWORD PTR [ecx+0x44],0x1
   0xb77dd5fa <+618>:	div    esi
   0xb77dd5fc <+620>:	test   edx,edx
   0xb77dd5fe <+622>:	jne    0xb77dd64f <start_input_pass+703>
   0xb77dd600 <+624>:	mov    DWORD PTR [ecx+0x48],esi
   0xb77dd603 <+627>:	mov    ecx,DWORD PTR [ebp+0x8]
   0xb77dd606 <+630>:	mov    DWORD PTR [ecx+0x164],0x1
   0xb77dd610 <+640>:	mov    eax,DWORD PTR [ecx+0x148]
   0xb77dd616 <+646>:	mov    DWORD PTR [ecx+0x168],0x0
   0xb77dd620 <+656>:	jmp    0xb77dd4cb <start_input_pass+315>
   0xb77dd625 <+661>:	mov    edi,DWORD PTR [ebp+0x8]
   0xb77dd628 <+664>:	mov    eax,DWORD PTR [edi]
   0xb77dd62a <+666>:	mov    DWORD PTR [eax+0x14],0x1a
   0xb77dd631 <+673>:	mov    edx,DWORD PTR [edi+0x148]
   0xb77dd637 <+679>:	mov    DWORD PTR [eax+0x18],edx
   0xb77dd63a <+682>:	mov    eax,DWORD PTR [edi]
   0xb77dd63c <+684>:	mov    DWORD PTR [eax+0x1c],0x4
   0xb77dd643 <+691>:	mov    eax,DWORD PTR [edi]
   0xb77dd645 <+693>:	mov    DWORD PTR [esp],edi
   0xb77dd648 <+696>:	call   DWORD PTR [eax]
   0xb77dd64a <+698>:	jmp    0xb77dd3c2 <start_input_pass+50>
   0xb77dd64f <+703>:	mov    esi,edx
   0xb77dd651 <+705>:	jmp    0xb77dd600 <start_input_pass+624>
End of assembler dump.
#0  0xb77dd58a in latch_quant_tables (cinfo=0x8136784) at jdinput.c:240
        ci = <value optimized out>
        qtblno = <value optimized out>
        compptr = 0x8138a20
        qtbl = 0x813a91c
#1  start_input_pass (cinfo=0x8136784) at jdinput.c:257
No locals.
#2  0xb77e0fd8 in master_selection (cinfo=0x8136784) at jdmaster.c:399
        use_c_buffer = <value optimized out>
#3  jinit_master_decompress (cinfo=0x8136784) at jdmaster.c:556
No locals.
#4  0xb77d9f80 in jpeg_start_decompress (cinfo=0x8136784) at jdapistd.c:42
No locals.
#5  0xb7d310b0 in DCTStream::reset (this=0x8136770) at DCTStream.cc:145
        c = <value optimized out>
        c2 = <value optimized out>
#6  0xb7dbd753 in ImageStream::reset (this=0x8128f68) at Stream.cc:421
No locals.
#7  0xb7d2bdd6 in SplashOutputDev::drawImage (this=0x80de700, state=0x8128c80, ref=0xbffff560, str=0x8136770, width=559, height=77, colorMap=0x8137168, interpolate=0, maskColors=0x0, inlineImg=0) at SplashOutputDev.cc:2274
        rgb = {r = -1210746167, g = -1209919371, b = 135395712}
        ctm = <value optimized out>
        srcMode = <value optimized out>
        src = <value optimized out>
        n = 135434088
        mat = {529.65000000000009, 0, -0, 72.900000000000006, 109.50000000000001, 430.94999999999993}
        imgData = {imgStr = 0x8128f68, colorMap = 0x8126190, lookup = 0xbffff4d4 "\r", maskColors = 0xb7abf516, colorMode = 3083640820, width = 668, height = 135396264, y = -1073745112}
        gray = <value optimized out>
        pix = <value optimized out>
        i = <value optimized out>
#8  0xb7d72cd9 in Gfx::doImage (this=0x810c8b8, ref=0xbffff560, str=0x8136770, inlineImg=0) at Gfx.cc:4131
        maskBits = -1209919417
        interpolate = 0
        maskColors = {-1073744904, -1209539832, -1211326476, -1212587096, -1073744904, 6, 135396200, 135396224, -1, -1209539832, -1209539832, 16, -1073744744, -1210276440, -1212587104, -1073744508, 0, -1212592140, -1212587104, 135396248, -1073744840, -1213453172, -1212587032, 135353720, -1073744776, -1209539832, -1073744520, 135396248, -1073744808, -1210111056, 6, -1073744784, 0, 135396200, 135434072, 135396248, -1073744760, -1210110850, 135434072, 135396248, 0, -1212592140, 13, 16, -1073744744, -1210373860, -1073744520, 0, -1073744696, -1210373733, 135396248, 3, -1073744712, -1210373609, 135273688, 16, 0, -1209539832, 135318780, 3, -1073744664, -1210746301, 135318780, -1073744544}
        maskInterpolate = -1209916956
        obj1 = {type = objNone, {booln = 0, intg = 0, real = 2.1219957909652723e-314, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1}, cmd = 0x0}}
        maskColorSpace = <value optimized out>
        obj2 = {type = objNone, {booln = 0, intg = 0, real = 9.1791390117275269e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135488940}, cmd = 0x0}}
        dict = 0x811fba8
        haveColorKeyMask = <value optimized out>
        i = <value optimized out>
        width = 559
        height = 77
        colorSpace = <value optimized out>
        maskWidth = -1209919405
        maskHeight = -1209919424
        maskDict = <value optimized out>
        bits = 8
        mask = <value optimized out>
        invert = <value optimized out>
        maskObj = {type = objNull, {booln = 0, intg = 0, real = 8.1129767717867517e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135341288}, cmd = 0x0}}
        smaskObj = {type = objNull, {booln = 0, intg = 0, real = -1.9973373413085938, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073744616}, cmd = 0x0}}
        maskInvert = <value optimized out>
        maskStr = 0x31
        csMode = streamCSNone
#9  0xb7d793e3 in Gfx::opXObject (this=0x810c8b8, args=0xbffff654, numArgs=1) at Gfx.cc:3738
        obj1 = {type = objStream, {booln = 135489392, intg = 135489392, real = 2.1286898563615841e-313, string = 0x8136770, name = 0x8136770 "h\271\347\267\001", array = 0x8136770, dict = 0x8136770, stream = 0x8136770, ref = {num = 135489392, gen = 10}, cmd = 0x8136770 "h\271\347\267\001"}}
        obj3 = {type = objNone, {booln = 0, intg = 0, real = 8.113092304226807e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135341304}, cmd = 0x0}}
        refObj = {type = objRef, {booln = 16, intg = 16, real = 7.9050503334599447e-323, string = 0x10, name = 0x10 <Address 0x10 out of bounds>, array = 0x10, dict = 0x10, stream = 0x10, ref = {num = 16, gen = 0}, cmd = 0x10 <Address 0x10 out of bounds>}}
        name = 0x81124e8 "R16"
        obj2 = {type = objName, {booln = 135434072, intg = 135434072, real = 2.1889091132168622e-314, string = 0x8128f58, name = 0x8128f58 "Image", array = 0x8128f58, dict = 0x8128f58, stream = 0x8128f58, ref = {num = 135434072, gen = 1}, cmd = 0x8128f58 "Image"}}
        opiDict = {type = objNull, {booln = 0, intg = 0, real = -1.2649360088136726e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1210348479}, cmd = 0x0}}
#10 0xb7d68256 in Gfx::execOp (this=0x810c8b8, cmd=0xbffff7f4, args=0xbffff654, numArgs=1) at Gfx.cc:794
        op = <value optimized out>
        name = 0x81124f8 "Do"
        argPtr = 0xbffff654
        i = 1
#11 0xb7d68879 in Gfx::go (this=0x810c8b8, topLevel=1) at Gfx.cc:665
        timer = {start_time = {tv_sec = 1319054257, tv_usec = 898888}, end_time = {tv_sec = 1753104, tv_usec = -1211289600}, active = 1}
        obj = {type = objCmd, {booln = 135341304, intg = 135341304, real = 4804.5079355921989, string = 0x81124f8, name = 0x81124f8 "Do", array = 0x81124f8, dict = 0x81124f8, stream = 0x81124f8, ref = {num = 135341304, gen = 1085457538}, cmd = 0x81124f8 "Do"}}
        numArgs = 1
        i = <value optimized out>
        lastAbortCheck = 0
        args = {{type = objName, {booln = 135341288, intg = 135341288, real = 4804.5079355921844, string = 0x81124e8, name = 0x81124e8 "R16", array = 0x81124e8, dict = 0x81124e8, stream = 0x81124e8, ref = {num = 135341288, gen = 1085457538}, cmd = 0x81124e8 "R16"}}, {type = objNone, {booln = 0, intg = 0, real = 4804.5078125, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1085457538}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 4804.5078125, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1085457538}, cmd = 0x0}}, {type = objNone, {booln = 486, intg = 486, real = 4804.507812500442, string = 0x1e6, name = 0x1e6 <Address 0x1e6 out of bounds>, array = 0x1e6, dict = 0x1e6, stream = 0x1e6, ref = {num = 486, gen = 1085457538}, cmd = 0x1e6 <Address 0x1e6 out of bounds>}}, {type = objNone, {booln = 730, intg = 730, real = 4804.5078125006639, string = 0x2da, name = 0x2da <Address 0x2da out of bounds>, array = 0x2da, dict = 0x2da, stream = 0x2da, ref = {num = 730, gen = 1085457538}, cmd = 0x2da <Address 0x2da out of bounds>}}, {type = objNone, {booln = 3656, intg = 3656, real = 4804.5078125033251, string = 0xe48, name = 0xe48 <Address 0xe48 out of bounds>, array = 0xe48, dict = 0xe48, stream = 0xe48, ref = {num = 3656, gen = 1085457538}, cmd = 0xe48 <Address 0xe48 out of bounds>}}, {type = objNone, {booln = 0, intg = 0, real = -1.6086048075139501e-40, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1213462882}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.8251752954228354e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1207978212}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 5.517189056509708e-313, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 26}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 3.6345592276647354e-139, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 590434330}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.529501319450299e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208083712}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 2.1219957909652723e-314, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.529501319450299e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208083712}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -7.0533797682403937e-40, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1211189048}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9980316162109375, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743888}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.649502914741219e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208040894}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9979629516601562, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743960}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 2.1219957909652723e-314, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 8.2027454777097579e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135353720}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.2959040042260189e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1210304280}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9979743957519531, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743948}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -7.2245764016269566e-40, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1211140180}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9980392456054688, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743880}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 7.0769973818104364e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135129328}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.529501319450299e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208083712}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.8659586859285448e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1207963660}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.998046875, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743872}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}}
#12 0xb7d69269 in Gfx::display (this=0x810c8b8, obj=0xbffff8f4, topLevel=1) at Gfx.cc:634
        obj2 = {type = objNone, {booln = 0, intg = 0, real = 7.8512380288413583e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135305040}, cmd = 0x0}}
        i = <value optimized out>
#13 0xb7db61f0 in Page::displaySlice (this=0x8109750, out=0x80de700, hDPI=90, vDPI=90, rotate=0, useMediaBox=0, crop=1, sliceX=0, sliceY=0, sliceW=744, sliceH=1052, printing=0, catalog=0x8101d48, abortCheckCbk=0, abortCheckCbkData=0x0, annotDisplayDecideCbk=0, annotDisplayDecideCbkData=0x0) at Page.cc:474
        gfx = 0x810c8b8
        obj = {type = objStream, {booln = 135353720, intg = 135353720, real = 6.6873623088815249e-316, string = 0x8115578, name = 0x8115578 "(\322\347\267\003", array = 0x8115578, dict = 0x8115578, stream = 0x8115578, ref = {num = 135353720, gen = 0}, cmd = 0x8115578 "(\322\347\267\003"}}
        i = <value optimized out>
#14 0xb7db9ed7 in PDFDoc::displayPageSlice (this=0x80ffb58, out=0x80de700, page=1, hDPI=90, vDPI=90, rotate=0, useMediaBox=0, crop=1, printing=0, sliceX=0, sliceY=0, sliceW=744, sliceH=1052, abortCheckCbk=0, abortCheckCbkData=0x0, annotDisplayDecideCbk=0, annotDisplayDecideCbkData=0x0) at PDFDoc.cc:414
No locals.
#15 0x0805e2d4 in ?? ()
No symbol table info available.
#16 0x0805f9aa in ?? ()
No symbol table info available.
#17 0x080646c7 in ?? ()
No symbol table info available.
#18 0x0805a5a1 in ?? ()
No symbol table info available.
#19 0x080711b2 in ?? ()
No symbol table info available.
#20 0x08061139 in ?? ()
No symbol table info available.
#21 0x08072143 in ?? ()
No symbol table info available.
#22 0xb7a69c76 in __libc_start_main (main=0x8071890, argc=2, ubp_av=0xbffffce4, init=0x8072280, fini=0x8072270, rtld_fini=0xb7ff1040 <_dl_fini>, stack_end=0xbffffcdc) at libc-start.c:228
        result = <value optimized out>
        unwind_buf = {cancel_jmp_buf = {{jmp_buf = {-1212592140, 0, 0, -1073742664, -270933799, 1561925321}, mask_was_saved = 0}}, priv = {pad = {0x0, 0x0, 0x2, 0x8051110}, data = {prev = 0x0, cleanup = 0x0, canceltype = 2}}}
        not_first_call = <value optimized out>
#23 0x08051131 in ?? ()
No symbol table info available.
siginfo:$1 = {si_signo = 11, si_errno = 0, si_code = 1, _sifields = {_pad = {0, 139108656, 138330864, 138903864, 135454464, 145079415, 145146344, -1073744232, 134567640, 145182112, 145229624, -1073744264, 707, 146768148, 145229624, -1073744264, 135473460, 145322592, -1216490102, 145297128, 145146344, 0, -1212647778, -1211907707, -1211907678, -1211906980, 141259416, 0, 13}, _kill = {si_pid = 0, si_uid = 139108656}, _timer = {si_tid = 0, si_overrun = 139108656, si_sigval = {sival_int = 138330864, sival_ptr = 0x83ec2f0}}, _rt = {si_pid = 0, si_uid = 139108656, si_sigval = {sival_int = 138330864, sival_ptr = 0x83ec2f0}}, _sigchld = {si_pid = 0, si_uid = 139108656, si_status = 138330864, si_utime = 138903864, si_stime = 135454464}, _sigfault = {si_addr = 0x0}, _sigpoll = {si_band = 0, si_fd = 139108656}}}
si_addr:$2 = (void *) 0x0
A debugging session is active.

	Inferior 1 [process 3099] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
