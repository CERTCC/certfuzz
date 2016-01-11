
Program received signal SIGSEGV, Segmentation fault.
0xb77db58a in ?? () from /usr/lib/libjpeg.so.62
#0  0xb77db58a in ?? () from /usr/lib/libjpeg.so.62
No symbol table info available.
#1  0xb77defd8 in jinit_master_decompress () from /usr/lib/libjpeg.so.62
No symbol table info available.
#2  0xb77d7f80 in jpeg_start_decompress () from /usr/lib/libjpeg.so.62
No symbol table info available.
#3  0xb7d310b0 in DCTStream::reset (this=0x812f1a0) at DCTStream.cc:145
        c = <value optimized out>
        c2 = <value optimized out>
#4  0xb7dbd753 in ImageStream::reset (this=0x8121078) at Stream.cc:421
No locals.
#5  0xb7d2bdd6 in SplashOutputDev::drawImage (this=0x80de8f8, state=0x812e9e8, ref=0xbffff560, str=0x812f1a0, width=253, height=2279, colorMap=0x812fb40, interpolate=0, maskColors=0x0, inlineImg=0) at SplashOutputDev.cc:2274
        rgb = {r = 0, g = -1211202632, b = -1209539832}
        ctm = <value optimized out>
        srcMode = <value optimized out>
        src = <value optimized out>
        n = 135401592
        mat = {90, 0, -0, 810.71124999999995, 106.29875, 81.496250000000032}
        imgData = {imgStr = 0x8121078, colorMap = 0x0, lookup = 0x1 <Address 0x1 out of bounds>, maskColors = 0x1, colorMode = splashModeMono1, width = 1, height = 134525848, y = 134745904}
        gray = <value optimized out>
        pix = <value optimized out>
        i = <value optimized out>
#6  0xb7d72cd9 in Gfx::doImage (this=0x81204b0, ref=0xbffff560, str=0x812f1a0, inlineImg=0) at Gfx.cc:4131
        maskBits = -1209919417
        interpolate = 0
        maskColors = {-837507378, -1209539832, 28, -1208083712, 0, 0, 1, 1156, 0, -1208083712, -1211137031, -1211182440, -1211222024, 1, -1207963660, -1073744656, -1208083272, -1073744700, -1208040734, -1073744716, -1211222024, -1073744728, -1207961004, 0, 0, 1, 0, 1, -1208083712, -1210111056, 6, -1073744784, 0, 135411016, 135458544, 135411976, 0, -1073744656, -1073744728, -1073744716, 0, -1208083712, 0, 24, -1073744744, -1211137031, -1073744520, 1, -1073744696, -1210373733, 135411976, 0, -1073744712, -1210373609, 135274176, 24, -1211222024, -1208083712, 135287476, -1, -1207963660, -1211137031, 1, -1073744640}
        maskInterpolate = -1209916956
        obj1 = {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}
        maskColorSpace = <value optimized out>
        obj2 = {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}
        dict = 0x81238e0
        haveColorKeyMask = <value optimized out>
        i = <value optimized out>
        width = 253
        height = 2279
        colorSpace = <value optimized out>
        maskWidth = -1209919405
        maskHeight = -1209919424
        maskDict = <value optimized out>
        bits = 8
        mask = <value optimized out>
        invert = <value optimized out>
        maskObj = {type = objNull, {booln = 0, intg = 0, real = -2.1936598783803562e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1209539832}, cmd = 0x0}}
        smaskObj = {type = objNull, {booln = 0, intg = 0, real = 3.719451198370257e-308, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1752808}, cmd = 0x0}}
        maskInvert = <value optimized out>
        maskStr = 0x31
        csMode = streamCSNone
#7  0xb7d793e3 in Gfx::opXObject (this=0x81204b0, args=0xbffff654, numArgs=1) at Gfx.cc:3738
        obj1 = {type = objStream, {booln = 135459232, intg = 135459232, real = 2.1286883662595962e-313, string = 0x812f1a0, name = 0x812f1a0 "h\271\347\267\001", array = 0x812f1a0, dict = 0x812f1a0, stream = 0x812f1a0, ref = {num = 135459232, gen = 10}, cmd = 0x812f1a0 "h\271\347\267\001"}}
        obj3 = {type = objNone, {booln = 0, intg = 0, real = 8.5481874734752517e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135401560}, cmd = 0x0}}
        refObj = {type = objRef, {booln = 24, intg = 24, real = 1.1857575500189917e-322, string = 0x18, name = 0x18 <Address 0x18 out of bounds>, array = 0x18, dict = 0x18, stream = 0x18, ref = {num = 24, gen = 0}, cmd = 0x18 <Address 0x18 out of bounds>}}
        name = 0x8122ea0 "I0"
        obj2 = {type = objName, {booln = 135458544, intg = 135458544, real = 6.6925413026074912e-316, string = 0x812eef0, name = 0x812eef0 "Image", array = 0x812eef0, dict = 0x812eef0, stream = 0x812eef0, ref = {num = 135458544, gen = 0}, cmd = 0x812eef0 "Image"}}
        opiDict = {type = objNull, {booln = 0, intg = 0, real = -1.2649360088136726e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1210348479}, cmd = 0x0}}
#8  0xb7d68256 in Gfx::execOp (this=0x81204b0, cmd=0xbffff7f4, args=0xbffff654, numArgs=1) at Gfx.cc:794
        op = <value optimized out>
        name = 0x8121058 "Do"
        argPtr = 0xbffff654
        i = 1
#9  0xb7d68879 in Gfx::go (this=0x81204b0, topLevel=1) at Gfx.cc:665
        timer = {start_time = {tv_sec = 1319055689, tv_usec = 695925}, end_time = {tv_sec = 1753104, tv_usec = -1211289600}, active = 1}
        obj = {type = objCmd, {booln = 135401560, intg = 135401560, real = 648.56886304962518, string = 0x8121058, name = 0x8121058 "Do", array = 0x8121058, dict = 0x8121058, stream = 0x8121058, ref = {num = 135401560, gen = 1082410125}, cmd = 0x8121058 "Do"}}
        numArgs = 1
        i = <value optimized out>
        lastAbortCheck = 0
        args = {{type = objName, {booln = 135409312, intg = 135409312, real = 648.56886305050648, string = 0x8122ea0, name = 0x8122ea0 "I0", array = 0x8122ea0, dict = 0x8122ea0, stream = 0x8122ea0, ref = {num = 135409312, gen = 1082410125}, cmd = 0x8122ea0 "I0"}}, {type = objNone, {booln = 0, intg = 0, real = 78.23394775390625, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1079217913}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 78.23394775390625, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1079217913}, cmd = 0x0}}, {type = objNone, {booln = 1340029796, intg = 1340029796, real = 648.56899999999996, string = 0x4fdf3b64, name = 0x4fdf3b64 <Address 0x4fdf3b64 out of bounds>, array = 0x4fdf3b64, dict = 0x4fdf3b64, stream = 0x4fdf3b64, ref = {num = 1340029796, gen = 1082410125}, cmd = 0x4fdf3b64 <Address 0x4fdf3b64 out of bounds>}}, {type = objNone, {booln = 0, intg = 0, real = 648.56884765625, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1082410125}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 648.56884765625, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1082410125}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.6051576132917111e-40, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1213466818}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.8263411757451536e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1207977796}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 5.517189056509708e-313, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 26}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 3.6345592276647354e-139, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 590434330}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.529501319450299e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208083712}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 2.1219957909652723e-314, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.529501319450299e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208083712}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -7.0533797682403937e-40, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1211189048}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9980316162109375, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743888}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.6499513302498029e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208040734}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9979629516601562, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743960}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 2.1219957909652723e-314, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 1}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 8.6905812058434695e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135421280}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.2959040042260189e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1210304280}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9979743957519531, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743948}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -7.2245764016269566e-40, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1211140180}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.9980392456054688, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743880}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 8.6130011723463025e-270, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 135410536}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.529501319450299e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1208083712}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -5.8659586859285448e-39, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1207963660}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = -1.998046875, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = -1073743872}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}, {type = objNone, {booln = 0, intg = 0, real = 0, string = 0x0, name = 0x0, array = 0x0, dict = 0x0, stream = 0x0, ref = {num = 0, gen = 0}, cmd = 0x0}}}
#10 0xb7d69269 in Gfx::display (this=0x81204b0, obj=0xbffff8f4, topLevel=1) at Gfx.cc:634
        obj2 = {type = objNone, {booln = 135421280, intg = 135421280, real = 7.7182026517903544e-270, string = 0x8125d60, name = 0x8125d60 "(\322\347\267\001", array = 0x8125d60, dict = 0x8125d60, stream = 0x8125d60, ref = {num = 135421280, gen = 135286616}, cmd = 0x8125d60 "(\322\347\267\001"}}
        i = <value optimized out>
#11 0xb7db61f0 in Page::displaySlice (this=0x8104f58, out=0x80de8f8, hDPI=90, vDPI=90, rotate=0, useMediaBox=0, crop=1, sliceX=0, sliceY=0, sliceW=765, sliceH=990, printing=0, catalog=0x8103ed8, abortCheckCbk=0, abortCheckCbkData=0x0, annotDisplayDecideCbk=0, annotDisplayDecideCbkData=0x0) at Page.cc:474
        gfx = 0x81204b0
        obj = {type = objArray, {booln = 135286488, intg = 135286488, real = 6.6840406067314051e-316, string = 0x8104ed8, name = 0x8104ed8 "\300\036\020\b\360N\020\b\b", array = 0x8104ed8, dict = 0x8104ed8, stream = 0x8104ed8, ref = {num = 135286488, gen = 0}, cmd = 0x8104ed8 "\300\036\020\b\360N\020\b\b"}}
        i = <value optimized out>
#12 0xb7db9ed7 in PDFDoc::displayPageSlice (this=0x80ffd40, out=0x80de8f8, page=1, hDPI=90, vDPI=90, rotate=0, useMediaBox=0, crop=1, printing=0, sliceX=0, sliceY=0, sliceW=765, sliceH=990, abortCheckCbk=0, abortCheckCbkData=0x0, annotDisplayDecideCbk=0, annotDisplayDecideCbkData=0x0) at PDFDoc.cc:414
No locals.
#13 0x0805e2d4 in ?? ()
No symbol table info available.
#14 0x0805f9aa in ?? ()
No symbol table info available.
#15 0x080646c7 in ?? ()
No symbol table info available.
#16 0x0805a5a1 in ?? ()
No symbol table info available.
#17 0x080711b2 in ?? ()
No symbol table info available.
#18 0x08061139 in ?? ()
No symbol table info available.
#19 0x08072143 in ?? ()
No symbol table info available.
#20 0xb7a68c76 in __libc_start_main (main=0x8071890, argc=2, ubp_av=0xbffffce4, init=0x8072280, fini=0x8072270, rtld_fini=0xb7ff10d0 <_dl_fini>, stack_end=0xbffffcdc) at libc-start.c:228
        result = <value optimized out>
        unwind_buf = {cancel_jmp_buf = {{jmp_buf = {-1212592140, 0, 0, -1073742664, -1756685588, 632024316}, mask_was_saved = 0}}, priv = {pad = {0x0, 0x0, 0x2, 0x8051110}, data = {prev = 0x0, cleanup = 0x0, canceltype = 2}}}
        not_first_call = <value optimized out>
#21 0x08051131 in ?? ()
No symbol table info available.
eax            0x8132d74	135474548
ecx            0x21	33
edx            0x1d68	7528
ebx            0xb77ead34	-1216434892
esp            0xbffff160	0xbffff160
ebp            0xbffff198	0xbffff198
esi            0x1	1
edi            0x8132d74	135474548
eip            0xb77db58a	0xb77db58a
eflags         0x10282	[ SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
process 12017
cmdline = '/usr/bin/xpdf'
cwd = '/home/fuzz'
exe = '/usr/bin/xpdf'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8080000    0x38000          0      /usr/bin/xpdf
	 0x8080000  0x8084000     0x4000    0x37000      /usr/bin/xpdf
	 0x8084000  0x8143000    0xbf000          0           [heap]
	0xb72e3000 0xb75c7000   0x2e4000          0        
	0xb75c7000 0xb75cb000     0x4000          0      /usr/lib/libXfixes.so.3.1.0
	0xb75cb000 0xb75cc000     0x1000     0x3000      /usr/lib/libXfixes.so.3.1.0
	0xb75cc000 0xb75d4000     0x8000          0      /usr/lib/libXrender.so.1.3.0
	0xb75d4000 0xb75d5000     0x1000     0x7000      /usr/lib/libXrender.so.1.3.0
	0xb75d5000 0xb75dd000     0x8000          0      /usr/lib/libXcursor.so.1.0.2
	0xb75dd000 0xb75de000     0x1000     0x7000      /usr/lib/libXcursor.so.1.0.2
	0xb75de000 0xb75e0000     0x2000          0        
	0xb75e0000 0xb75e4000     0x4000          0      /usr/lib/libXdmcp.so.6.0.0
	0xb75e4000 0xb75e5000     0x1000     0x3000      /usr/lib/libXdmcp.so.6.0.0
	0xb75e5000 0xb7609000    0x24000          0      /usr/lib/libexpat.so.1.5.2
	0xb7609000 0xb760b000     0x2000    0x23000      /usr/lib/libexpat.so.1.5.2
	0xb760b000 0xb760c000     0x1000          0        
	0xb760c000 0xb760e000     0x2000          0      /usr/lib/libXau.so.6.0.0
	0xb760e000 0xb760f000     0x1000     0x1000      /usr/lib/libXau.so.6.0.0
	0xb760f000 0xb7612000     0x3000          0      /lib/libuuid.so.1.3.0
	0xb7612000 0xb7613000     0x1000     0x2000      /lib/libuuid.so.1.3.0
	0xb7613000 0xb7615000     0x2000          0      /lib/i686/cmov/libdl-2.11.2.so
	0xb7615000 0xb7616000     0x1000     0x1000      /lib/i686/cmov/libdl-2.11.2.so
	0xb7616000 0xb7617000     0x1000     0x2000      /lib/i686/cmov/libdl-2.11.2.so
	0xb7617000 0xb762f000    0x18000          0      /usr/lib/libxcb.so.1.1.0
	0xb762f000 0xb7630000     0x1000    0x17000      /usr/lib/libxcb.so.1.1.0
	0xb7630000 0xb765d000    0x2d000          0      /usr/lib/libfontconfig.so.1.4.4
	0xb765d000 0xb765f000     0x2000    0x2c000      /usr/lib/libfontconfig.so.1.4.4
	0xb765f000 0xb7660000     0x1000          0        
	0xb7660000 0xb7784000   0x124000          0      /usr/lib/libxml2.so.2.7.7
	0xb7784000 0xb7789000     0x5000   0x123000      /usr/lib/libxml2.so.2.7.7
	0xb7789000 0xb778a000     0x1000          0        
	0xb778a000 0xb77a6000    0x1c000          0      /usr/lib/libopenjpeg-2.1.3.0.so
	0xb77a6000 0xb77a7000     0x1000    0x1c000      /usr/lib/libopenjpeg-2.1.3.0.so
	0xb77a7000 0xb77ca000    0x23000          0      /lib/libpng12.so.0.44.0
	0xb77ca000 0xb77cb000     0x1000    0x22000      /lib/libpng12.so.0.44.0
	0xb77cb000 0xb77ea000    0x1f000          0      /usr/lib/libjpeg.so.62.0.0
	0xb77ea000 0xb77eb000     0x1000    0x1e000      /usr/lib/libjpeg.so.62.0.0
	0xb77eb000 0xb781b000    0x30000          0      /usr/lib/liblcms.so.1.0.18
	0xb781b000 0xb781d000     0x2000    0x2f000      /usr/lib/liblcms.so.1.0.18
	0xb781d000 0xb781f000     0x2000          0        
	0xb781f000 0xb7832000    0x13000          0      /usr/lib/libz.so.1.2.3.4
	0xb7832000 0xb7833000     0x1000    0x13000      /usr/lib/libz.so.1.2.3.4
	0xb7833000 0xb7834000     0x1000          0        
	0xb7834000 0xb78a7000    0x73000          0      /usr/lib/libfreetype.so.6.6.0
	0xb78a7000 0xb78ab000     0x4000    0x73000      /usr/lib/libfreetype.so.6.6.0
	0xb78ab000 0xb78b9000     0xe000          0      /usr/lib/libXext.so.6.4.0
	0xb78b9000 0xb78ba000     0x1000     0xd000      /usr/lib/libXext.so.6.4.0
	0xb78ba000 0xb78c1000     0x7000          0      /usr/lib/libXp.so.6.2.0
	0xb78c1000 0xb78c2000     0x1000     0x6000      /usr/lib/libXp.so.6.2.0
	0xb78c2000 0xb78d7000    0x15000          0      /usr/lib/libICE.so.6.3.0
	0xb78d7000 0xb78d8000     0x1000    0x14000      /usr/lib/libICE.so.6.3.0
	0xb78d8000 0xb78da000     0x2000          0        
	0xb78da000 0xb78e1000     0x7000          0      /usr/lib/libSM.so.6.0.1
	0xb78e1000 0xb78e2000     0x1000     0x6000      /usr/lib/libSM.so.6.0.1
	0xb78e2000 0xb78e3000     0x1000          0        
	0xb78e3000 0xb79fc000   0x119000          0      /usr/lib/libX11.so.6.3.0
	0xb79fc000 0xb7a00000     0x4000   0x118000      /usr/lib/libX11.so.6.3.0
	0xb7a00000 0xb7a4e000    0x4e000          0      /usr/lib/libXt.so.6.0.0
	0xb7a4e000 0xb7a52000     0x4000    0x4d000      /usr/lib/libXt.so.6.0.0
	0xb7a52000 0xb7b92000   0x140000          0      /lib/i686/cmov/libc-2.11.2.so
	0xb7b92000 0xb7b93000     0x1000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7b93000 0xb7b95000     0x2000   0x140000      /lib/i686/cmov/libc-2.11.2.so
	0xb7b95000 0xb7b96000     0x1000   0x142000      /lib/i686/cmov/libc-2.11.2.so
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
A debugging session is active.

	Inferior 1 [process 12017] will be killed.

Quit anyway? (y or n) [answered Y; input not from terminal]
