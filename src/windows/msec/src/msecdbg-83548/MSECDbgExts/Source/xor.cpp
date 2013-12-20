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
#include "debugger.h"

#define DEFAULT_LEN 256
#define MAX_INSTRUCTION_BYTES 9 

typedef enum _EncodingType 
{
    EncodingNone = 0,
    EncodingXor,
    EncodingSub,
    EncodingAdd,
    EncodingRol,
} EncodingType;

typedef enum _KeyModifierType 
{
    None = 0,
    KeyModAdd,
} KeyModifierType;

WINDBG_EXTENSION_APIS ExtensionApis;
DWORD CalcCRC32(BYTE* Data, DWORD DataLen);
HRESULT DecodeEx(PDEBUG_CLIENT5 Client, PCSTR args, BOOL fDisassemble, EncodingType EncType, int uiIncrement, KeyModifierType KeyModType);

static bool bLeaveTransformedBufferInMemory = false;

BYTE Rol(UINT Value, UINT Places)
{
    return (BYTE) (((Value << Places) | (Value >> (8 - Places))) & 0xFF);
}

void DisassembleBufferInTarget(PDEBUG_CONTROL4 pDebugControl, ULONG64 Address, LPBYTE buffer, ULONG cb)
{
    HRESULT hr = E_FAIL;

    //
    // Save current contents in target memory.
    //
    ULONG cbBytesRead      = 0;
    BYTE* lpOriginalBuffer = new BYTE[cb];    
    if(!lpOriginalBuffer) return;

    if(ReadMemory((ULONG)Address, lpOriginalBuffer, cb,  &cbBytesRead) == FALSE) 
    {
        delete [] lpOriginalBuffer;
        return;
    }

    if(cb != cbBytesRead) 
    {
        delete [] lpOriginalBuffer;
        return;
    }
    
    //
    // Overwrite the memory contents with XOR-ed buffer
    // 
    ULONG cbBytesWritten = 0;
    if(WriteMemory((ULONG)Address, buffer, cb,  &cbBytesWritten) == FALSE) goto cleanup;
    if(cb != cbBytesWritten) goto cleanup;

    ULONG64 CurrentOffset = Address;
    ULONG64 NextOffset    = 0;
    do
    {
        ULONG   cchInstruction = 0;        
        hr = pDebugControl->Disassemble(CurrentOffset, 0, NULL, 0, &cchInstruction, &NextOffset);
        if(FAILED(hr)) goto cleanup;

        CHAR* pszInstructionBuffer = new CHAR[cchInstruction + 1];
        if(!pszInstructionBuffer) goto cleanup;

        hr = pDebugControl->Disassemble(CurrentOffset, 0, pszInstructionBuffer, cchInstruction+1, NULL, &NextOffset);
        if(FAILED(hr)) 
        {
            delete [] pszInstructionBuffer;
            goto cleanup;
        }

        pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "%s", pszInstructionBuffer);

        delete [] pszInstructionBuffer;
        pszInstructionBuffer = NULL;

        CurrentOffset = NextOffset;
    } 
    while(CurrentOffset <= Address + cb);

cleanup:
    // Restore original buffer in target memory
    if(lpOriginalBuffer && !bLeaveTransformedBufferInMemory)
    {
        WriteMemory((ULONG)Address, lpOriginalBuffer, cb,  NULL);        
    }

    if(lpOriginalBuffer) delete [] lpOriginalBuffer;
}

HRESULT DecodeEx(PDEBUG_CLIENT5 pClient, ULONG64 Address, ULONG64 Len, ULONG64 Key, BOOL fDisassemble, EncodingType EncType, int uiIncrement, KeyModifierType KeyModType)
{
	LPBYTE buffer = NULL;
	ULONG cb;
    CHAR AsciiDump[18];
    UINT uIdx = 0;
    BYTE decodeb = 0;
    ZeroMemory(AsciiDump, sizeof AsciiDump);
	
	DEBUGGER_CONTROLS objDebugger( pClient );
	if ( !objDebugger.fInitialized )
		return E_INVALIDARG;

    if(!Address) return E_INVALIDARG;
    if(!Len) Len = DEFAULT_LEN;

	buffer = (LPBYTE)LocalAlloc( LPTR, (ULONG) Len+8); 
	if (buffer != NULL)
	{
		if ( objDebugger.pDebugDataSpaces->ReadVirtual(Address, buffer, (ULONG)Len, &cb)==S_OK && cb == (ULONG)Len ) 
        {
			for (UINT i=0; i < cb; i++)
            {
                BYTE b = buffer[i];
                switch (EncType)
                {
                    case EncodingXor:
                        {
                            //
                            // If we have a 4byte XOR do 4 bytes at a time
                            //
                            if (Key > 0xFFFFFF)
                            {
                                BYTE b0, b1, b2, b3;
                                b0 = buffer[i];
                                b1 = buffer[i + 1];
                                b2 = buffer[i + 2];
                                b3 = buffer[i + 3];
                                
                                buffer[i + 3] = ( BYTE ) (b3 ^ ((Key & 0xFF000000) >> 24));
                                buffer[i + 2] = ( BYTE ) (b2 ^ ((Key & 0x00FF0000) >> 16));
                                buffer[i + 1] = ( BYTE ) (b1 ^ ((Key & 0x0000FF00) >> 8));
                                buffer[i + 0] = ( BYTE ) (b0 ^ ((Key & 0x000000FF))); 
                                i+=3; //loop i++ takes care of last increment
                            }
                            else if (Key > 0xFF)
                            {
                                BYTE b0, b1;
                                b0 = buffer[i];
                                b1 = buffer[i + 1];
                                
                                buffer[i + 1] = ( BYTE ) (b1 ^ ((Key & 0x0000FF00) >> 8));
                                buffer[i + 0] = ( BYTE ) (b0 ^ ((Key & 0x000000FF))); 
                                i+=1; //loop i++ takes care of last increment
                            }
                            else
                            {
                                decodeb = ( BYTE ) (b ^ Key);
                                buffer[i] = decodeb;
                            }
                        }
                        break;
                    case EncodingSub:
                        decodeb = ( BYTE ) (b - Key);
                        buffer[i] = decodeb;
                        break;
                    case EncodingAdd:
                        decodeb = ( BYTE ) (b + Key);
                        buffer[i] = decodeb;
                        break;
                    case EncodingRol:
                        decodeb = Rol(b , (UINT) Key);
                        buffer[i] = decodeb;
                        break;
                }
                Key+= uiIncrement;
                if (KeyModType == KeyModAdd)
                {
                    DWORD DecodedDWORD = *(PDWORD)&buffer[i-3];
                    Key+= DecodedDWORD;
                }
            }

			for (UINT i=0; i < cb; i++)
            {
                decodeb = buffer[i];
                if (i % 16 == 0)
                {
                    objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "0x%08x  ", (Address + i));                        
                    uIdx = 0;
                    ZeroMemory(AsciiDump, sizeof AsciiDump);
                }

                if (isprint(decodeb))
                {
                    AsciiDump[uIdx++]=decodeb;
                }
                else
                {
                    if (decodeb == 0x20)
                        AsciiDump[uIdx++]=' ';
                    else if (decodeb == 0xd)
                        AsciiDump[uIdx++]='r';
                    else if (decodeb == 0xa)
                        AsciiDump[uIdx++]='n';
                    else
                        AsciiDump[uIdx++]='.';
                }
                
                objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "%02X ", decodeb);

                if (strlen(AsciiDump) == 16)
                {
                    objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "%s\n", AsciiDump);
                }                
                else if(i == cb-1) // take care of the last line.
                {
                    for(unsigned int z=0; z<15-(i%16); z++)
                        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "   ");

                    objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, "%s\n", AsciiDump);
                }
            }
        }
		else
        {
            goto cleanup;
        }

        if (fDisassemble)
        {
            DisassembleBufferInTarget(objDebugger.pDebugControl, Address, buffer, cb);
        }
	}        

cleanup:

    if (buffer) LocalFree(buffer);    
    return S_OK;
}

HRESULT Decode(PDEBUG_CLIENT5 Client, ULONG64 address, ULONG64 len, ULONG64 key, BOOL fDisassemble, EncodingType EncType)
{
    return DecodeEx(Client, address, len, key, fDisassemble, EncType, 0, None);
}

typedef HRESULT (CALLBACK *XORCALL)(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key);

HRESULT CALLBACK
XOR(PDEBUG_CLIENT5 pClient, PCSTR args, char* functionName, XORCALL xorCall)
{
    DEBUGGER_CONTROLS objDebugger( pClient );
	if ( !objDebugger.fInitialized )
		return E_INVALIDARG;

    if(strlen(args) <= 0)
    {
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, " Usage  : !%s [-b] address [len] key\n", functionName);
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, " Example: !%s eax 64 DD\n", functionName);
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, " Example: !%s -b eax 64 DD (Leave the transformed buffer in memory)\n", functionName);
        objDebugger.pDebugControl->Output(DEBUG_OUTPUT_NORMAL, " Example: !%s 0x00123456 DD (using default length = 256)\n", functionName);
        return E_INVALIDARG;
    }

    // Get the windbg-style extension APIS. 
    ExtensionApis.nSize = sizeof (ExtensionApis);
    objDebugger.pDebugControl->GetWindbgExtensionApis64(&ExtensionApis);

    //
    // Parse arguments.
    //
    ULONG64 addr = 0;
    ULONG64 len  = 0;
    ULONG64 key  = 0;    

    LPCSTR offset = strstr(args, "-b");
    if(offset == NULL)
    {
        bLeaveTransformedBufferInMemory = false;
    }
    else
    {
        bLeaveTransformedBufferInMemory = true;        
        args =  offset + strlen("-b");  // eat up "-b"
    }

    if (!GetExpressionEx(args, &addr, &args)) return E_INVALIDARG;
    GetExpressionEx(args, &len, &args);
    if (!GetExpressionEx(args, &key, &args))
    {
        key = len;
        len = DEFAULT_LEN;
    }   

    return (xorCall)(pClient, addr, len, key);
}

HRESULT CALLBACK
Xora(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, FALSE, EncodingXor);
}

HRESULT CALLBACK
xora(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "xora", Xora);
}

HRESULT CALLBACK
Xoru(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, TRUE, EncodingXor);
}

HRESULT CALLBACK
xoru(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "xoru", Xoru);
}

HRESULT CALLBACK
Xorui(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return DecodeEx(client, address, len, key, TRUE, EncodingXor, 1, None);
}

HRESULT CALLBACK
xorui(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "xorui", Xorui);
}

HRESULT CALLBACK
Xorud(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return DecodeEx(client, address, len, key, TRUE, EncodingXor, -1, None);
}

HRESULT CALLBACK
xorud(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "xorud", Xorud);
}

HRESULT CALLBACK
Xorua(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return DecodeEx(client, address, len, key, TRUE, EncodingXor, 0, KeyModAdd);
}

HRESULT CALLBACK
xorua(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "xorua", Xorui);
}

HRESULT CALLBACK
Suba(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, FALSE, EncodingSub);
}

HRESULT CALLBACK
suba(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "suba", Suba);
}

HRESULT CALLBACK
Subu(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, TRUE, EncodingSub);
}

HRESULT CALLBACK
subu(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "subu", Subu);
}

HRESULT CALLBACK
Adda(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, FALSE, EncodingAdd);
}

HRESULT CALLBACK
adda(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "adda", Adda);
}

HRESULT CALLBACK
Addu(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, TRUE, EncodingAdd);
}

HRESULT CALLBACK
addu(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "addu", Addu);
}

HRESULT CALLBACK
Rola(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, FALSE, EncodingRol);
}

HRESULT CALLBACK
rola(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "rola", Rola);
}

HRESULT CALLBACK
Rolu(PDEBUG_CLIENT5 client, ULONG64 address, ULONG64 len, ULONG64 key)
{
    return Decode(client, address, len, key, TRUE, EncodingRol);
}

HRESULT CALLBACK
rolu(PDEBUG_CLIENT5 client, PCSTR args)
{
    return XOR(client, args, "rolu", Rolu);
}
