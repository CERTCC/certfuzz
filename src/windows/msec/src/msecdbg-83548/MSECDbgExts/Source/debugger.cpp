//
// debugger.cpp
//
// The MSEC Debugger Functions
//
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

#define DEBUGGER_MODULE
#include "stdafx.h"

#include "debugger.h"
#include "utility.h"


// global variable used to hold the user include aditions list
LPSTR* _lppszAditionalExcludeSymbols = NULL;
// global variable used to check for initialization
BOOL _bInitialized = FALSE;


///
// Find a register flag, and return the value. This function returns false if no such flag could be found
bool
GetProcessorFlagByName( const DEBUGGER_CONTROLS &objControls, PCWSTR pwzFlag )
{
	ULONG iRegister;
	DEBUG_VALUE objRegister;

	if( objControls.pDebugRegisters->GetIndexByNameWide( pwzFlag, &iRegister ) == S_OK )
	{
		if( objControls.pDebugRegisters->GetValue( iRegister, &objRegister ) == S_OK )
		{
			return (objRegister.I64 != 0);
		}
	}

	return( false );
}


/// Calculate the stack hash given a stack to work from
void
CalculateStackHash( const DEBUGGER_CONTROLS& objDebugger, ULONG cStackFrames, __in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames, HASHING_MODE eHashMode, __out ULONG* pdwMajorHash, __out ULONG* pdwMinorHash )
{
	

	CalculateStackHash( objDebugger, cStackFrames, pStackFrames,eHashMode, NULL, NULL, NULL, pdwMajorHash, pdwMinorHash );
}


void CalculateStackHash( const DEBUGGER_CONTROLS& objDebugger, 
					ULONG cStackFrames, 
					__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames, 
					HASHING_MODE eHashMode,
					_Out_writes_opt_(cStackFrames)  bool* pfUnknownStackFrames,
					_Out_writes_opt_(cStackFrames)  bool* pfExcludedStackFrames, 
					__out_opt bool *pfStackContainsUnknownSymbols, 
					__out ULONG* pdwMajorHash, 
					__out ULONG* pdwMinorHash )
{
	// Initialize the hashes
	*pdwMajorHash = 0UL;
	*pdwMinorHash = 0UL;
	
	DetermineUnknownandExcludedFrames( objDebugger, 
				 cStackFrames, 
				pStackFrames, 
				pfUnknownStackFrames,
				pfExcludedStackFrames, 
				pfStackContainsUnknownSymbols);

	switch (eHashMode)
	{
		case CUSTOMV1:
			CalculateHashCustomV1(objDebugger,cStackFrames,pStackFrames,pdwMajorHash,pdwMinorHash);
			break;
		case CUSTOMV2:
			CalculateHashCustomV2(objDebugger,cStackFrames,pStackFrames,pdwMajorHash,pdwMinorHash);
			break;
		case SHA256:
			CalculateHashSHA256(objDebugger,cStackFrames,pStackFrames,pdwMajorHash,pdwMinorHash);
			break;
	}

}

void	
DetermineUnknownandExcludedFrames(const DEBUGGER_CONTROLS& objDebugger, ULONG cStackFrames, __in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames, _Out_writes_opt_(cStackFrames)  bool* pfUnknownStackFrames,_Out_writes_opt_(cStackFrames)  bool* pfExcludedStackFrames,  __out_opt bool *pfStackContainsUnknownSymbols )
{
	CHAR pszName[128];
	ULONG cchName;
	ULONG64 offDisplacement;
	ULONG64 offInstructionPointer;
	pszName[127]=0;

	if( pfStackContainsUnknownSymbols )
	{
		*pfStackContainsUnknownSymbols = false;
	}

	// Initialize the hashes
	objDebugger.pDebugRegisters->GetInstructionOffset( &offInstructionPointer );


	// Iterate through the stack frames, constructing the hash
	for (ULONG iFrame =0; iFrame < cStackFrames; iFrame++)
	{
		HRESULT dwResult = objDebugger.pDebugSymbols->GetNameByOffset(pStackFrames[iFrame].InstructionOffset, pszName, 127, (PULONG)&cchName, (PULONG64)&offDisplacement);

		if( dwResult == E_FAIL )
		{
			if( pfStackContainsUnknownSymbols )
			{
				*pfStackContainsUnknownSymbols = true;
			}

			if( pfUnknownStackFrames )
			{
				pfUnknownStackFrames[iFrame] = true;
			}
		}
		else
		{
			if( pfUnknownStackFrames )
			{
				pfUnknownStackFrames[iFrame] = false;
			}
		}
		
		if( !IsSymbolExcluded( pszName  ) )
		{
			
			if( pfExcludedStackFrames )
			{
				pfExcludedStackFrames[iFrame] = false;
			}
		}
		else
		{
			if( pfExcludedStackFrames )
			{
				pfExcludedStackFrames[iFrame] = true;
			}
		}
	}
}

void 
CalculateHashCustomV1(const DEBUGGER_CONTROLS& objDebugger,ULONG cStackFrames,__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames,   __inout ULONG* pdwMajorHash, __inout ULONG* pdwMinorHash ){

	CHAR pszName[128];
	CHAR pszDisplacement[16];
	ULONG cchName;
	ULONG64 offDisplacement;
	
	ULONG dwSalt = 0;
	ULONG cHash = 0;
	pszName[127]=0;

	// Initialize the hashes
	*pdwMajorHash = 0UL;
	*pdwMinorHash = 0UL;

	// Iterate through the stack frames, constructing the hash
	for (ULONG iFrame =0; iFrame < cStackFrames; iFrame++)
	{
		HRESULT dwResult = objDebugger.pDebugSymbols->GetNameByOffset(pStackFrames[iFrame].InstructionOffset, pszName, 127, (PULONG)&cchName, (PULONG64)&offDisplacement);

		if( dwResult == E_FAIL )
		{
			strcpy_s( pszName, "Unknown" );
			offDisplacement = 0;
		} else {
			_strlwr_s( pszName );
		}
		
		if( !IsSymbolExcluded( pszName ) )
		{
			for (int iBuffer = 0; pszName[iBuffer] != 0 && (ULONG)iBuffer < cchName; iBuffer++)
			{
				*pdwMinorHash ^= ((ULONG)pszName[iBuffer] << (dwSalt * 8));

				
				if (cHash < MAJOR_HASH_STACK_DEPTH ) 
				{
					*pdwMajorHash ^= ((ULONG)pszName[iBuffer] << (dwSalt * 8));
				}
				
				dwSalt = (dwSalt + 1) % 4;
					
			}
			
			// update the hash count
			++cHash;
			
			// add displacement for the long hash, mixing in frame number
			*pdwMinorHash ^= ((ULONG)'+' << (dwSalt * 8));
			
			_ltoa_s((LONG)offDisplacement, pszDisplacement, sizeof(pszDisplacement), 16);

			for (int iBuffer = 0; pszDisplacement[iBuffer] != 0 && iBuffer < 16; iBuffer++)
			{
				*pdwMinorHash ^= ((ULONG)pszDisplacement[iBuffer] << (dwSalt * 8));
			}

			
		}
	}	
}

void 
CalculateHashCustomV2(const DEBUGGER_CONTROLS& objDebugger,ULONG cStackFrames,__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames,   __inout ULONG* pdwMajorHash, __inout ULONG* pdwMinorHash ){

	CHAR pszName[128];
	ULONG cchName;
	ULONG64 offDisplacement;
	
	ULONG cHash = 0;
	pszName[127]=0;

	// Initialize the hashes
	*pdwMajorHash = 0UL;
	*pdwMinorHash = 0UL;

	// Iterate through the stack frames, constructing the hash
	for (ULONG iFrame =0; iFrame < cStackFrames; iFrame++)
	{
		HRESULT dwResult = objDebugger.pDebugSymbols->GetNameByOffset(pStackFrames[iFrame].InstructionOffset, pszName, 127, (PULONG)&cchName, (PULONG64)&offDisplacement);

		if( dwResult == E_FAIL )
		{
			strcpy_s( pszName, "Unknown" );
			offDisplacement = 0;
		}
		
		if( !IsSymbolExcluded( pszName ) )
		{
			for (int iBuffer = 0; pszName[iBuffer] != 0 && (ULONG)iBuffer < cchName; iBuffer++)
			{
				*pdwMinorHash = ROL(*pdwMinorHash,5) ^ (ULONG) ::tolower( pszName[iBuffer] );

				if (cHash < MAJOR_HASH_STACK_DEPTH ) 
				{
					*pdwMajorHash = ROL(*pdwMajorHash,5) ^ (ULONG) ::tolower(pszName[iBuffer] );
				}
					
			}
			// add displacement for the long hash, mixing in frame number
			*pdwMinorHash ^= offDisplacement * (iFrame + 1);

			// update the hash count
			++cHash;
		}
	}	
}

void
CalculateHashSHA256(const DEBUGGER_CONTROLS& objDebugger,ULONG cStackFrames,__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames ,__inout ULONG* pdwMajorHash, __inout ULONG* pdwMinorHash )
{
	
	CHAR pszName[128];
	size_t cchName;
	ULONG64 offDisplacement;
	
	ULONG cHash = 0;

	CHAR buffer[65];
	CHAR * bufferSeperator ="+0x";
	
	pszName[127]=0;
	// Initialize the hashes
	*pdwMajorHash = 0UL;
	*pdwMinorHash = 0UL;

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hMajorHash = 0;
	HCRYPTHASH hMinorHash = 0;
	DWORD rgbHash[8];
	DWORD cbHash = sizeof(rgbHash);

	if(!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT))
	{
		OutputDebugStringA("HASH : FAIL : CryptAcquireContext");
		goto cleanup;
	}
				
	if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hMajorHash))
	{
		OutputDebugStringA("HASH : FAIL : CryptCreateHash");
		goto cleanup;
	}
	if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hMinorHash)) 
	{
		OutputDebugStringA("HASH : FAIL : CryptCreateHash");
		goto cleanup;
	}
		

	// Iterate through the stack frames, constructing the hash
	for (ULONG iFrame =0; iFrame < cStackFrames; iFrame++)
	{
		HRESULT dwResult = objDebugger.pDebugSymbols->GetNameByOffset(pStackFrames[iFrame].InstructionOffset, pszName, 127, (PULONG)&cchName, (PULONG64)&offDisplacement);

		if( dwResult == E_FAIL )
		{
			strcpy_s( pszName, "Unknown" );
			offDisplacement = 0;
		}
		
		if( !IsSymbolExcluded( pszName ) )
		{
			
			cchName = strnlen_s(pszName,_countof(pszName));
			
			// get hash of the symbol part of the frame for minor
			if(!CryptHashData(hMinorHash,(const BYTE *) pszName,(DWORD)cchName* sizeof(CHAR), 0)) {
				OutputDebugStringA("HASH : FAIL : CryptHashData");
				goto cleanup;
			}
    
			// get hash of the symbol part of the frame for major
			if (cHash < MAJOR_HASH_STACK_DEPTH ){
				if(!CryptHashData(hMajorHash,(const BYTE *) pszName, (DWORD)cchName* sizeof(CHAR), 0)) {
					OutputDebugStringA("HASH : FAIL : CryptHashData");
					goto cleanup;
				}
			}

			

			if (offDisplacement != 0){

				
				// get has of the seperator of the symbol and displacement
				if(!CryptHashData(hMinorHash,(const BYTE *) bufferSeperator, sizeof(bufferSeperator), 0)) {
					OutputDebugStringA("HASH : FAIL : CryptHashData");
					goto cleanup;
				}

				
				_ui64toa_s(offDisplacement,buffer,sizeof(buffer),16);
	
				size_t bufferSize = strnlen_s(buffer,_countof(buffer));
				
				// get has of displacement viewed as a string.  This way it should be the same if a person copies the frame from a debug session;
				if(!CryptHashData(hMinorHash,(const BYTE *) buffer, (DWORD)bufferSize * sizeof(CHAR), 0)) {
					OutputDebugStringA("HASH : FAIL : CryptHashData");
					goto cleanup;
				}
			}
		}
			// update the hash count
			++cHash;
	}

	if (!CryptGetHashParam(hMinorHash, HP_HASHVAL, (BYTE *)rgbHash, &cbHash, 0)){
		OutputDebugStringA("HASH : FAIL : CryptGetHashParam");
		goto cleanup;
	}
	for (int i = 0; (DWORD)i < _countof(rgbHash); i++)
		*pdwMinorHash ^= rgbHash[i];

	if (!CryptGetHashParam(hMajorHash, HP_HASHVAL, (BYTE *)rgbHash, &cbHash, 0)){
		OutputDebugStringA("HASH : FAIL : CryptGetHashParam");
		goto cleanup;
	}

	for (int i = 0; (DWORD)i < _countof(rgbHash); i++)
		*pdwMajorHash ^= rgbHash[i];

cleanup:
	if (hMajorHash)	
	{
		if (!CryptDestroyHash(hMajorHash)){
			OutputDebugStringA("HASH : FAIL : CryptDestroyHash");
		}
	}
	if (hMinorHash)	
	{
		if(!CryptDestroyHash(hMinorHash)){
			OutputDebugStringA("HASH : FAIL : CryptDestroyHash");
		}
	}
	if (hProv)
	{
		if(!CryptReleaseContext(hProv, 0)){
			OutputDebugStringA("HASH : FAIL : CryptReleaseContext");
		}
	}
}


bool
LoadCustomExcludeList(HMODULE hModule)
{


	if (_bInitialized)
		return FALSE;

	CHAR lpFileName [MAX_PATH];
	DWORD cFileName = GetModuleFileNameA(hModule,lpFileName,_countof(lpFileName));
	if (cFileName == 0)
	{
		return FALSE;
	}
	LPSTR lpszLastIndex= strrchr(lpFileName,L'\\');
	if (lpszLastIndex == NULL)
	{
		return FALSE;
	}

	int spaceLeft = _countof(lpFileName) + lstrlenA(lpszLastIndex) - lstrlenA(lpFileName) -1;
	if (spaceLeft <= lstrlenA("\\Exploitable.ini"))
	{
		return FALSE;
	}
	
	errno_t error = strncpy_s(lpszLastIndex,spaceLeft,"\\Exploitable.ini",_countof("\\Exploitable.ini"));
	if (error != 0)
	{
		return FALSE;
	}
	
	LPSTR * ppszFilterList = NULL;
	LPSTR lpSectionHeapBuffer = NULL;
	const int MAX_SECTION_SIZE = 32767; //max possible size according to msdn GetPrivateProfileSectionA
	LPSTR lpSectionBuffer = new CHAR[MAX_SECTION_SIZE]; 
	
	if (lpSectionBuffer == NULL)
	{
		goto fail;
	}
	
	DWORD cSectionBuffer = GetPrivateProfileSectionA("HashExcludePatterns",lpSectionBuffer,MAX_SECTION_SIZE,lpFileName);
	
	if (cSectionBuffer <= 2 || cSectionBuffer == (MAX_SECTION_SIZE-2)) //no entries or, buffer is not big enough
	{ 
		goto fail;
	}

	
	lpSectionHeapBuffer =  new CHAR [cSectionBuffer+1];   
	
	if (lpSectionHeapBuffer == NULL)
	{
		goto fail;
	}


	error = memcpy_s(lpSectionHeapBuffer,(cSectionBuffer+1) * sizeof(CHAR),lpSectionBuffer,cSectionBuffer+1 );
	if (error != 0)
	{
		goto fail;
	}

	if (lpSectionBuffer !=NULL)
	{
		delete [] lpSectionBuffer;
		lpSectionBuffer = NULL;
	}

	lpSectionHeapBuffer[cSectionBuffer] = NULL;
	lpSectionHeapBuffer[cSectionBuffer-1] = NULL;
	

	int cLineCount = 0;
	for (DWORD index = 0; index <= cSectionBuffer; index++)
	{
		if (lpSectionHeapBuffer[index] == NULL)
			++cLineCount;
	}

	ppszFilterList = new LPSTR [cLineCount];
		
	if (!ppszFilterList)
	{
		goto fail;
	}
	int cLineIndex = 0;
	LPSTR token = lpSectionHeapBuffer;
	while( *token != NULL )
    {
		ppszFilterList[cLineIndex++] = token;
		token += (lstrlenA(token)+1) * sizeof(CHAR);
	}
	
	ppszFilterList[cLineCount-1] = NULL;
	
	_lppszAditionalExcludeSymbols = ppszFilterList;
	return TRUE;

fail:
	
	if (lpSectionBuffer) {
		delete [] lpSectionBuffer;
		lpSectionBuffer = NULL;
	}

	if (lpSectionHeapBuffer){
		delete[] lpSectionHeapBuffer;
		lpSectionHeapBuffer = NULL;
	}
	if (ppszFilterList){
		delete[] ppszFilterList;
		ppszFilterList = NULL;
	}
		
	return FALSE;
}

void UnloadCustomExcludeList(){
	if (_bInitialized)
	{
		if (_lppszAditionalExcludeSymbols)
		{
			if (*_lppszAditionalExcludeSymbols){
				free(*_lppszAditionalExcludeSymbols);
				*_lppszAditionalExcludeSymbols = NULL;
			}
			free(_lppszAditionalExcludeSymbols);
			_lppszAditionalExcludeSymbols = NULL;
		}
		_bInitialized = false;
	}
}


///
// Determine whether or not a symbol is excluded from the hash algorithm or blame assignment
bool
IsSymbolExcluded( PCSTR pszSymbol )
{
	



	// Check Hardcoded List
	PCSTR *ppszExcludedSymbols = EXCLUDED_SYMBOLS;

	while( *ppszExcludedSymbols != NULL )
	{
		if( wildcmp( *ppszExcludedSymbols, pszSymbol ) )
		{
			return( true );
		}

		ppszExcludedSymbols++;
	}

	//check for aditional entries
	if (_lppszAditionalExcludeSymbols )
	{
		LPSTR * ppszAditionalExcludedSymbols = _lppszAditionalExcludeSymbols;
		while( *ppszAditionalExcludedSymbols != NULL )
		{
			if( wildcmp( *ppszAditionalExcludedSymbols, pszSymbol ) )
			{
				return( true );
			}

			ppszAditionalExcludedSymbols++;
		}
	}

	return( false );
}

// Get the value (or address of for larger items) of a symbol as a 64 bit value
bool
GetSymbolValue( const DEBUGGER_CONTROLS& objDebugger, ULONG iStackFrame, PCSTR pszSymbol, PULONG64 pqwValue )
{
	ULONG iPreviousScopeIndex;
	PDEBUG_SYMBOL_GROUP2 pSymbolGroup = NULL;
	PSTR pszSymbolBuffer = NULL;
	size_t cSymbolBuffer = 0;
	bool returnVal = false;

	if( pszSymbol == NULL )
	{
		return( returnVal );
	}

	if( pqwValue == NULL )
	{
		return( returnVal );
	}

	*pqwValue = 0UL;

	// Cache the current scope index so that we can restore it on the way out
	HRESULT hResult = objDebugger.pDebugSymbols->GetCurrentScopeFrameIndex( &iPreviousScopeIndex );

	if( hResult != S_OK )
	{
		return( returnVal );
	}


	
	// From this point on, everything is done inside of the try/finally block, to allow us to manage
	// memory and scope on the way out if we hit failure conditions
	__try
	{
		cSymbolBuffer = strlen( pszSymbol ) + 1;

		if( cSymbolBuffer != 0 )
		{
			pszSymbolBuffer = new char[cSymbolBuffer];
		}
		else
		{
			__leave;
		}

		hResult = objDebugger.pDebugSymbols->SetScopeFrameByIndex( iStackFrame );

		if( (hResult != S_OK) && (hResult != S_FALSE) )
		{
			__leave;
		}

		// Get the symbol group for the scope		
		hResult = objDebugger.pDebugSymbols->GetScopeSymbolGroup2( DEBUG_SCOPE_GROUP_ALL, NULL, &pSymbolGroup );

		if( hResult != S_OK )
		{
			__leave;
		}

		// And now iterate to find the symbol with the specified name
		ULONG cSymbols;

		hResult = pSymbolGroup->GetNumberSymbols( &cSymbols );

		if( hResult != S_OK )
		{
			__leave;
		}

		bool fSymbolFound = false;
		ULONG iSymbol =0;
		for( ULONG iSearchSymbol = 0; iSearchSymbol < cSymbols && !fSymbolFound; iSearchSymbol++ )
		{
			hResult = pSymbolGroup->GetSymbolName( iSearchSymbol, pszSymbolBuffer, (ULONG) cSymbolBuffer, NULL );

			if( hResult == S_OK )
			{
				if( strcmp( pszSymbol, pszSymbolBuffer ) == 0 )
				{
					iSymbol = iSearchSymbol;
					fSymbolFound = true;
				}
			}
		}

		if( !fSymbolFound )
		{
			__leave;
		}

		// Now, given the symbol, it's time to look up the value

		// Now we check to see if it's in a register. If it is, we're going to use the 
		// register
		ULONG iRegister;
		hResult = pSymbolGroup->GetSymbolRegister( iSymbol, &iRegister );

		if( hResult == S_OK )
		{
			DEBUG_VALUE objValue;

			hResult = objDebugger.pDebugRegisters->GetValue( iRegister, &objValue );

			if( hResult != S_OK )
			{
				__leave;
			}

			switch( objValue.Type )
			{
				case DEBUG_VALUE_INT8:
					*pqwValue = (ULONG64) objValue.I8;
					break;

				case DEBUG_VALUE_INT16:
					*pqwValue = (ULONG64) objValue.I16;
					break;

				case DEBUG_VALUE_INT32:
					*pqwValue = (ULONG64) objValue.I32;
					break;

				case DEBUG_VALUE_INT64:
					*pqwValue = (ULONG64) objValue.I64;
					break;

				default:
					__leave;
			}

			returnVal = true;
			__leave;
		}

		// Otherwise, we need to pull the value from memory

		// First we determine the size
		ULONG cbSymbolValue;

		hResult = pSymbolGroup->GetSymbolSize( iSymbol, &cbSymbolValue );

		if( hResult != S_OK )
		{
			__leave;
		}

		// If the symbol size is larger than our UINT64, we're going to assume it is a 
		// pointer and return that. Otherwise, we'll return the contents
		if( cbSymbolValue > sizeof( UINT64 ) )
		{
			hResult = pSymbolGroup->GetSymbolOffset( iSymbol, pqwValue );

			returnVal =( hResult == S_OK );
			__leave;
		}
		else
		{
			UINT64 offSymbol;

			hResult = pSymbolGroup->GetSymbolOffset( iSymbol, &offSymbol );

			if( hResult != S_OK )
			{
				__leave;
			}

			// Note that we are assuming a Little-Endian byte order here
			hResult = objDebugger.pDebugDataSpaces->ReadVirtual( offSymbol,
													(PVOID) pqwValue,
													cbSymbolValue,
													NULL );

			returnVal =( hResult == S_OK );
			__leave;
		}
	}
	__finally
	{
		if( pSymbolGroup != NULL )
		{
			pSymbolGroup->Release();
		}

		if( pszSymbolBuffer != NULL )
		{
			delete[] pszSymbolBuffer;
		}

		objDebugger.pDebugSymbols->SetScopeFrameByIndex( iPreviousScopeIndex );
	}

	return( returnVal );
}
