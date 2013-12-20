Microsoft Public License (Ms-PL)
This license governs use of the accompanying software. If you use the software, you accept this license. If you do not accept the license, do not use the software.

Definitions
The terms "reproduce," "reproduction," "derivative works," and "distribution" have the same meaning here as under U.S. copyright law. A "contribution" is the original software, or any additions or changes to the software. A "contributor" is any person that distributes its contribution under this license. "Licensed patents" are a contributor's patent claims that read directly on its contribution.
Grant of Rights
(A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution or any derivative works that you create.
(B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution in the software or derivative works of the contribution in the software.
Conditions and Limitations
(A) No Trademark License- This license does not grant you rights to use any contributors' name, logo, or trademarks. 
(B) If you bring a patent claim against any contributor over patents that you claim are infringed by the software, your patent license from such contributor to the software ends automatically. 
(C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and attribution notices that are present in the software. 
(D) If you distribute any portion of the software in source code form, you may do so only under this license by including a complete copy of this license with your distribution. If you distribute any portion of the software in compiled or object code form, you may only do so under a license that complies with this license. 
(E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express warranties, guarantees, or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement.

Requirements:
	Windows Debugger
	Visual C++ 2012 (Any Edition)
		Please note that Visual C++ 2012 Express edition will only build the x86 version of the MSEC Debugger Extensions.
	
Build Instructions:
	Create a DEBUGGER_ROOT environment variable, and point it to the Windows Debugger SDK directory
	Build All
	
Alternate Build Instructions:
	Copy the include directory from the SDK to a sibling directory to the source directory named DebuggerDependencies\Include
	Copy the X86 library directories from the SDK to a sibling directory to the source directory named DebuggerDependencies\Lib\x86
	Copy the X64 library directories from the SDK to a sibling directory to the source directory named DebuggerDependencies\Lib\x64
	Build All
	
Installation Instructions :

	Build and copy the correct version (x86 or x64) to your Windows Debugger winext sub-directory

Usage Instructions:

	You may need to explicitly load the MSEC DLL. If you installed it to the winext sub-directory, you can load
	it with !load winext\msec.dll

	Exploitable.ini
	!exploitable now supports extending the exclude list. The exclude list is a black used to remove stack frames from the Hash calculation. The file must be called Exploitable.ini and co-located with msec.dll
	The file must contain a section called [HashExcludePatterns]. The entries under this section are strings that can use the asterisk character for wildcard matching.
	
	!exploitable
	Gives an analysis, including a proposed bug title
	
	!exploitable -hash:CustomV1 
	Use version 1 of custom hash algorithm to calculate major and minor hash. Default algorithm used between 1.0.1 and 1.0.6
	
	!exploitable -hash:CustomV2 
	Use version 2 of custom hash algorithm to calculate major and minor hash. Default algorithm used between 1.0.7 and 1.5.0
	
	!exploitable -hash:SHA256
	Use SHA256 hash algorithm to calculate major and minor hash. This is the default hashing algorithm. The 8 DWORDS are XOR'd together to keep hash lengths at 32 bits for backwards compatibility.

	!exploitable -v
	Gives a verbose analysis

	!exploitable -m
	Gives the same output as -v, but formatted for easy machine parsing	
	
	!exploitable -jit:address
	Use the JIT Exception Record to determine the exception
	
	!ror [-n <Rotation Count>] [-c] <Value>
	Get the API name for hash value <Value> using rotation count <Rotation Count>. Use -c to do a reverse lookup from an API name to a hash value. Run !ror without options for examples.

	!xoru [-b] <addr> [<length>] <key>
	Do the Xor transformation on the buffer from address <addr> to address <addr> + <length> using the key <key> and disassemble the buffer. Use -b to leave the transformed buffer in memory. Run !xoru without options for examples. You can do other types of transformation using xora, xorui, xorua, suba, subu, adda, addu, rola, or rolu.

	!metadis -addr:address
	Disassemble the basic block starting at address and report the result to the user in human readable form


Known Issues:

	!exploitable
	
		The instruction set is known to be incomplete. 	
		
		KERNEL_MODE_EXCEPTION_NOT_HANDLED / KERNEL_MODE_EXCEPTION_NOT_HANDLED_M does not currently differentiate between read and write access violations.
