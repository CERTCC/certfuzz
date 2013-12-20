/*
 * KiUserExceptionDispatcher hook
 *
 * ------------------------------------------------------------------------
 * Copyright (C) 2011 Carnegie Mellon University. All Rights Reserved.
 * ------------------------------------------------------------------------
 * Author: David Warren <dwarren@cert.org>
 * ------------------------------------------------------------------------
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are 
 * met:
 * 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following acknowledgments 
 *    and disclaimers.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. All advertising materials for third-party software mentioning 
 *    features or use of this software must display the following 
 *    disclaimer:
 * 
 *    "Neither Carnegie Mellon University nor its Software Engineering 
 *     Institute have reviewed or endorsed this software"
 * 
 * 4. The names "Department of Homeland Security," "Carnegie Mellon 
 *    University," "CERT" and/or "Software Engineering Institute" shall 
 *    not be used to endorse or promote products derived from this software 
 *    without prior written permission. For written permission, please 
 *    contact permission@sei.cmu.edu.
 * 
 * 5. Products derived from this software may not be called "CERT" nor 
 *    may "CERT" appear in their names without prior written permission of
 *    permission@sei.cmu.edu.
 * 
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 * 
 *    "This product includes software developed by CERT with funding 
 *     and support from the Department of Homeland Security under 
 *     Contract No. FA 8721-05-C-0003."
 * 
 * THIS SOFTWARE IS PROVIDED BY CARNEGIE MELLON UNIVERSITY ``AS IS'' AND
 * CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AS TO ANY MATTER, AND ALL SUCH WARRANTIES, INCLUDING 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE 
 * EXPRESSLY DISCLAIMED. WITHOUT LIMITING THE GENERALITY OF THE FOREGOING, 
 * CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND 
 * RELATING TO EXCLUSIVITY, INFORMATIONAL CONTENT, ERROR-FREE OPERATION, 
 * RESULTS TO BE OBTAINED FROM USE, FREEDOM FROM PATENT, TRADEMARK AND 
 * COPYRIGHT INFRINGEMENT AND/OR FREEDOM FROM THEFT OF TRADE SECRETS. 
 *
 */

#include "targetver.h"
#include <stdint.h>

#define WIN32_LEAN_AND_MEAN       
#include <windows.h>

uintptr_t KUEDaddr;
uintptr_t returnp;
uintptr_t myhook;
uintptr_t GetCurrentProcessp = (uintptr_t) &GetCurrentProcess;
uintptr_t OpenProcessp = (uintptr_t) &OpenProcess;
uintptr_t TerminateProcessp = (uintptr_t) &TerminateProcess;
uintptr_t TerminateJobObjectp = (uintptr_t) &TerminateJobObject;
uintptr_t OpenJobObjectAp = (uintptr_t) &OpenJobObjectA;

char *jobname = "fuzzjob";

// the __asm doesn't like the MS defines for these
#define EXCEPTION_ACCESS_VIOLATION		 0xC0000005;
#define EXCEPTION_ILLEGAL_INSTRUCTION	 0xC000001D;
#define EXCEPTION_GUARD_PAGE			 0x80000001;
#define EXCEPTION_INT_DIVIDE_BY_ZERO	 0xC0000094;
#define EXCEPTION_STACK_OVERFLOW		 0xC00000FD;
#define EXCEPTION_INVALID_DISPOSITION	 0xC0000026;
#define EXCEPTION_PRIVILEGED_INSTRUCTION 0xC0000096;

void __declspec(naked) myKiUserExceptionDispatcher(
		IN PEXCEPTION_RECORD ExceptionRecord,
		IN PCONTEXT Context) {

		__asm {
		// save things we clobber
		pushfd //flags
		push eax

		/*
		typedef struct _EXCEPTION_RECORD {
		  DWORD                    ExceptionCode;
		  DWORD                    ExceptionFlags;
		  struct _EXCEPTION_RECORD *ExceptionRecord;
		  PVOID                    ExceptionAddress;
		  DWORD                    NumberParameters;
		  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
		} EXCEPTION_RECORD, *PEXCEPTION_RECORD; 
		*/

		// [esp] = saved flags
		// [esp+4] = saved eax
		// [[esp+8]] is the ExceptionCode of the EXCEPTION_RECORD
		mov eax, DWORD PTR [esp+8]
		mov eax, [eax]

		// some exceptions we may care about
		// we cast a wide net so the downstream app can do additional filtering

		cmp eax, EXCEPTION_ACCESS_VIOLATION
		je WeCareAboutThisException
		cmp eax, EXCEPTION_ILLEGAL_INSTRUCTION
		je WeCareAboutThisException
		cmp eax, EXCEPTION_GUARD_PAGE
		je WeCareAboutThisException
		cmp eax, EXCEPTION_INT_DIVIDE_BY_ZERO
		je WeCareAboutThisException
		cmp eax, EXCEPTION_STACK_OVERFLOW
		je WeCareAboutThisException
		cmp eax, EXCEPTION_INVALID_DISPOSITION
		je WeCareAboutThisException
		cmp eax, EXCEPTION_PRIVILEGED_INSTRUCTION
		je WeCareAboutThisException
		
		// apathy, pass on to KiUserExceptionDispatcher

		// put back stuff we clobbered
		pop eax
		popfd

		// this is the code we overwrote with our JMP
		mov ecx, [esp+4]
		mov ebx, [esp]
		jmp [returnp]

WeCareAboutThisException:
		// terminate the fuzzjob
		push jobname // pointer to "fuzzjob"
		push TRUE // inherit children
		push JOB_OBJECT_ALL_ACCESS
		call [OpenJobObjectAp]
		mov  ebx, DWORD PTR [esp+8]
		push DWORD PTR [ebx]
		push eax // handle
		call [TerminateJobObjectp]
		// TerminateJobObject doesn't kill the current
		// process for some reason, even if we are in
		// the job, so kill ourself
		call [GetCurrentProcessp]
		mov  ebx, DWORD PTR [esp+8]
		push DWORD PTR [ebx] //exitcode
		push eax // handle
		call [TerminateProcessp]
		
		}
	
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	// code to paste into KiUserExceptionDispatcher
	// 0x41s will be replaced by the real &KiUserExceptionDispatcher
	uint8_t code[7] = {0xff, 0x25, 0x41, 0x41, 0x41, 0x41, 0x90};

	// signature for KiUserExceptionDispatcher in ntdll.dll for XP SP3
	uint8_t sig[7] = {0x8b,0x4c,0x24,0x04,0x8B,0x1C,0x24};

	HANDLE hProc;
	HANDLE hJob;
	BOOL result = FALSE;
	DWORD out;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// are we in a job we care about?

		hProc = GetCurrentProcess();
		hJob = OpenJobObjectA(JOB_OBJECT_ALL_ACCESS, TRUE, jobname);
		if (hJob != NULL) {
			IsProcessInJob( hProc, hJob, &result);
		}
		if (result) {
			// we are in the fuzzjob, hook
			myhook = (uintptr_t) myKiUserExceptionDispatcher;
			KUEDaddr = (uintptr_t) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"KiUserExceptionDispatcher");
		
			// check function sig
			if (memcmp( (void *) sig, (void *) KUEDaddr, 7)) {
				// signature check failed
				break;
			}
		
			if (!VirtualProtect((void *)KUEDaddr, 7, PAGE_EXECUTE_READWRITE, &out)) {
				// VirtualProtect failed
				break;
			}
			// copy the address of our hook function in the JMP code
			*((uint32_t *)&code[2]) = (uint32_t) &myhook;

			// paste the JMP code into &KiUserExceptionDispatcher 
			memcpy((void *)KUEDaddr,code,7);

			// remember where we should JMP back to
			returnp = KUEDaddr + 7;
		}

		break;

	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

