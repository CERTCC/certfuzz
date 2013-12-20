//
// Developed by the Microsoft Security Engineering Center (MSEC)
// Copyright 2008-2013, Microsoft Corporation
//
//	Microsoft Public License (Ms-PL)
//	This license governs use of the accompanying software. If you use the software, you accept this license. If you do not accept the license, do not use the software.
//
//	Definitions
//		The terms "reproduce," "reproduction," "derivative works," and "distribution" have the same meaning here as under U.S. copyright law. A "contribution" is the original software, or any additions or changes to the software. A "contributor" is any person that distributes its contribution under this license. "Licensed patents" are a contributor's patent claims that read directly on its contribution.
//	Grant of Rights
//		(A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution or any derivative works that you create.
//		(B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution in the software or derivative works of the contribution in the software.
//	Conditions and Limitations
//		(A) No Trademark License- This license does not grant you rights to use any contributors' name, logo, or trademarks. 
//		(B) If you bring a patent claim against any contributor over patents that you claim are infringed by the software, your patent license from such contributor to the software ends automatically. 
//		(C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and attribution notices that are present in the software. 
//		(D) If you distribute any portion of the software in source code form, you may do so only under this license by including a complete copy of this license with your distribution. If you distribute any portion of the software in compiled or object code form, you may only do so under a license that complies with this license. 
//		(E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express warranties, guarantees, or conditions. You may have additional consumer rights under your local laws which this license cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties of merchantability, fitness for a particular purpose and non-infringement.
//


#include "stdafx.h"
#include <stdio.h>
#include "debugger.h"

DWORD GetHash(BYTE* apiName, int size, unsigned int n, bool fXor)
{
    if(n > 32) return 0;

    DWORD hash = 0;

    if(fXor)
    {
        while (size)
        {
            hash = ((hash<<(32-n))|(hash>>n))^(*apiName++);
            size--;
        }
    }
    else
    {
        while (size)
        {
            hash = ((hash<<(32-n))|(hash>>n))+(*apiName++);
            size--;
        }
    }

    return hash;
}

DWORD GetHash(char* apiName, unsigned int n, bool fXor)
{
    if(n > 32) return 0; 

    DWORD hash = 0;

    if(fXor)
    {
        while (*apiName)
            hash = ((hash<<(32-n))|(hash>>n))^(*apiName++);
    }
    else
    {
        while (*apiName)
            hash = ((hash<<(32-n))|(hash>>n))+(*apiName++);
    }

    return hash;
}

//
// Return API name given a hash value
//
BOOL ScanExportTableForHash(char* dllName, DWORD dwRotationCount, DWORD dwHashValue, char* OUT outBuffer, bool fXor, bool fModuleAndFunction)
{
    #define RVA(offset) ((DWORD)h+(offset))

    HMODULE h = LoadLibraryA(dllName);

    if (!h)
    {
        return FALSE;
    }   

    // Get the dllName as a filename
    char * dllFilename = dllName, *pos;
    while ((pos = strchr(dllFilename,'\\')) != NULL)
	dllFilename = pos+1;
   
    IMAGE_NT_HEADERS *nt;
    unsigned short ofs = * (unsigned short*) RVA(0x3c);
    nt = (IMAGE_NT_HEADERS*) RVA(ofs);

    // Check if there are some exports
    if (nt->OptionalHeader.DataDirectory[0].Size > 0)
    {
        IMAGE_EXPORT_DIRECTORY *ied = (IMAGE_EXPORT_DIRECTORY*) RVA(nt->OptionalHeader.DataDirectory[0].VirtualAddress);
        DWORD *sym = (DWORD *) RVA(ied->AddressOfNames);
    
        for (unsigned int t=0;t<ied->NumberOfNames;++t)
        {
            char* funcName = (char*) RVA(sym[t]);

            if(fModuleAndFunction)
            {
                // First get the hash value of the module name in UNICODE.
                // Make it uppercase, also.
                BYTE ModuleNameBuffer[MAX_PATH] = {0,};
                for(unsigned int i=0; i<strlen(dllName); ++i)
                {
                    ModuleNameBuffer[i*2] = dllFilename[i];

                    if(dllFilename[i] > 0x61)
                        ModuleNameBuffer[i*2] -= 0x20;                   
                }                                

                // Calc hash for module name
                DWORD ModuleHash = GetHash(ModuleNameBuffer, (int)strlen(dllFilename)*2+2, dwRotationCount, fXor);

                BYTE FunctionNameBuffer[MAX_PATH] = {0,};
                // Get the hash value of the function name in ANSI.
                memcpy(FunctionNameBuffer, funcName, strlen(funcName));
                
                DWORD FunctionHash = GetHash(FunctionNameBuffer, (int)strlen(funcName)+1, dwRotationCount, fXor);

                if(ModuleHash + FunctionHash == dwHashValue)
                {
                    sprintf_s(outBuffer, MAX_PATH, "%s (%s)", funcName, dllFilename);
                    FreeLibrary(h);
                    return TRUE;
                }
            }
            else
            {
                if(dwHashValue == GetHash(funcName, dwRotationCount, fXor))
                {
                    sprintf_s(outBuffer, MAX_PATH, "%s (%s)", funcName, dllFilename);
                    FreeLibrary(h);
                    return TRUE;
                }
            }
        }
    }

    FreeLibrary(h);
    return FALSE;
}

HRESULT CALLBACK
ror(PDEBUG_CLIENT5 pClient, PCSTR pszArgs)
{
    HRESULT hr = E_FAIL;

	DEBUGGER_CONTROLS objDebugger( pClient );

	if ( !objDebugger.fInitialized )
		return E_INVALIDARG;

    //
    // Parse the args
    //
    char  seps[]    = " \t";
    char* token     = NULL;
    char *nextToken = NULL;

    int   argc = 0;
    char* argv[5] = {NULL,}; // we take max 5 args.
    char* args = (char*)pszArgs;

    // Establish string and get the first token:
    token = strtok_s( args, seps, &nextToken);

    // While there are tokens in args
    while ((token != NULL))
    {
        // Get next token
        if (token != NULL)
        {
            argv[argc++] = token;
            if(argc > 5) break;
            token = strtok_s( NULL, seps, &nextToken);
        }
    }

    if (argc < 1)
    {
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "Usage: %s [OPTION]\n", "!ror");                
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "-n ROTATION_COUNT Use ROTATION_COUNT. Default = 13.\n");                
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "-c API_NAME       Get hash value for API_NAME.\n");                
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "-x                Use the XOR hash accumulator instead of ADD.\n");                
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "-u HASH_VALUE     Get module name and API name given HASH_VALUE where \n");                
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "                  HASH_VALUE = Hash(Module name in uppercase UNICODE) + Hash(API name in ANSI)\n");                
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "                  where both names include the terminating NULL bytes.\n");                        
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "\n"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "Example: Get module name and API name for hash value 0x726774C.\n"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "         %s -u 0x726774C\n", "!ror"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "Example: Get API name for hash value 0x0E8AFE98 using default rotation count 13.\n"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "         %s 0x0E8AFE98\n", "!ror"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "Example: Get API name for hash value 0xA9F72DC9 using rotation count 15.\n"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "         %s -n 15 0xA9F72DC9\n", "!ror");        
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "Example: Get hash value for WinExec using rotation count 15.\n"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "         %s -n 15 -c WinExec\n", "!ror");                
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "Example: Get API name for hash value 0xd95d2399 using rotation count 25 via XOR instead of ADD.\n"); 
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "         %s -x -n 25 d95d2399\n", "!ror");        
        return 0;
    }

    int     i = 0;
    DWORD   dwRotationCount = 13; // Default 
    DWORD   dwHashValue = 0;
    char*   pszApiName  = NULL;
    bool    fXor = false;
    bool    fModuleAndFunction = false;

    while(argv[i] && i<argc)
    {
        if(strcmp(argv[i],"-n") == 0)
        {
            ++i;
            if(argv[i] != NULL && i<argc)
            {
                dwRotationCount = atoi(argv[i]);
            }           
            else
            {
                // the "-n" switch must be followed by a number.
                return E_INVALIDARG;
            }
        }
        else if(strcmp(argv[i],"-u") == 0)
        {
            fModuleAndFunction = true;
        }    
        else if(strcmp(argv[i],"-x") == 0)
        {
            fXor = true;
        }   
        else if (strcmp(argv[i],"-c") == 0)
        {
            ++i;
            if(argv[i] && i<argc)
                pszApiName = argv[i];
            else
            {
                // the "-c" switch must be followed by a string.
                return E_INVALIDARG;
            }
        }    
        else
        {    
            // Parse hash value.
            // Handle various formats such as 0x1234, 0n1234, 1234, eip, @eip, etc.
            //
            // Get the windbg-style extension APIS.   
            ExtensionApis.nSize = sizeof (ExtensionApis);
            objDebugger.pDebugControl->GetWindbgExtensionApis64(&ExtensionApis);

            ULONG64 dwHashValue64 = 0;
            PCSTR   pcszRemainder = NULL;
            if (!GetExpressionEx(argv[i], &dwHashValue64, &pcszRemainder)) return E_INVALIDARG;
            dwHashValue = (ULONG)dwHashValue64;
        }

        ++i;
    }

    if(pszApiName)
    {
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "0x%08X\n", GetHash(pszApiName, dwRotationCount, fXor));        
    }
    else
    {
        char* commonDLLs[] = 
        {
            "kernel32.dll",
            "urlmon.dll",
            "wininet.dll",
            "winhttp.dll",
            "advapi32.dll",
            "ntdll.dll",
            "gdi32.dll",
            "user32.dll",
            "shell32.dll",
            "shlwapi.dll",
            "ws2_32.dll",
            "psapi.dll",
            NULL
        };

        char apiNameOut[MAX_PATH];
        int idx = 0;
        while ( *(commonDLLs + idx) != NULL ) 
        {
            if(ScanExportTableForHash(commonDLLs[idx++], dwRotationCount, dwHashValue, apiNameOut, fXor, fModuleAndFunction) == TRUE) 
            {
                objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "%s\n", apiNameOut);
                break;
            }
        }   
    }

    return hr;

}
