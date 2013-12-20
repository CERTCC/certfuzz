//
// debugger.h
//
//
// Definitions for the Debugger Enginer Hooks for the MSEC Debugger Extension
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

#pragma once


#ifndef IMAGE_FILE_MACHINE_ARMNT
#define IMAGE_FILE_MACHINE_ARMNT	0x01c4
#endif


typedef enum _HASHING_MODE
{
	CUSTOMV1=0,
	CUSTOMV2,
	SHA256
} HASHING_MODE;


// Definitions
#define ANALYSIS_STACK_DEPTH			64
#define MAJOR_HASH_STACK_DEPTH			5

///
/// A helper encapsulation of the Debugging Engine COM objects
///
/// It provides simple access and instance creation/release management
/// for the debugging extensions
///
typedef struct _DEBUGGER_CONTROLS
{
	_DEBUGGER_CONTROLS()
	{
		fInitialized = false;
		pDebugClient = NULL;
		pDebugControl = NULL;
		pDebugRegisters = NULL;
		pDebugDataSpaces = NULL;
		pDebugSymbols = NULL;
	}

	_DEBUGGER_CONTROLS( PDEBUG_CLIENT5 pClient )
	{
		fInitialized = false;
		pDebugClient = pClient;
		pDebugControl = NULL;
		pDebugRegisters = NULL;
		pDebugDataSpaces = NULL;
		pDebugSymbols = NULL;
		pSystemObjects = NULL;

		if( pDebugClient != NULL )
		{
			fInitialized = (pClient->QueryInterface(__uuidof(IDebugControl4), (void **)&pDebugControl)) == S_OK;
			fInitialized = fInitialized && (pClient->QueryInterface(__uuidof(IDebugRegisters2), (void **)&pDebugRegisters) == S_OK);
			fInitialized = fInitialized && (pClient->QueryInterface(__uuidof(IDebugDataSpaces4), (void **)&pDebugDataSpaces) == S_OK);
			fInitialized = fInitialized && (pClient->QueryInterface(__uuidof(IDebugSymbols3), (void **)&pDebugSymbols) == S_OK);
			fInitialized = fInitialized && (pClient->QueryInterface(__uuidof(IDebugSystemObjects4), (void **) &pSystemObjects) == S_OK);
		}
	}

	virtual ~_DEBUGGER_CONTROLS()
	{
		if( pDebugControl != NULL )
		{
			pDebugControl->Release();
			pDebugControl = NULL;
		}

		if( pDebugRegisters != NULL )
		{
			pDebugRegisters->Release();
			pDebugRegisters = NULL;
		}

		if( pDebugDataSpaces != NULL )
		{
			pDebugDataSpaces->Release();
			pDebugDataSpaces = NULL;
		}

		if( pDebugSymbols != NULL )
		{
			pDebugSymbols->Release();
			pDebugSymbols = NULL;
		}

		if( pSystemObjects != NULL )
		{
			pSystemObjects->Release();
			pSystemObjects = NULL;
		}
	}

	bool fInitialized;
	PDEBUG_CLIENT5 pDebugClient;
	PDEBUG_CONTROL4 pDebugControl;
	PDEBUG_REGISTERS2 pDebugRegisters;
	PDEBUG_DATA_SPACES4 pDebugDataSpaces;
	PDEBUG_SYMBOLS3 pDebugSymbols;
	PDEBUG_SYSTEM_OBJECTS4 pSystemObjects;
} DEBUGGER_CONTROLS;




///
// A helper class to log output events
/// NOTE: This class does not work on the stack, only the heap.
///        In the Release function, it will delete itself if the refcount goes to zero.
///		   So if you allocate this class, DONT DELETE IT.
///
class OUTPUT_MONITOR : public IDebugOutputCallbacksWide
{
public:
	OUTPUT_MONITOR( )
	{
		lRefCount = 0;
		ppwzOutput = NULL;
		cpwzOutput = 0;
		cpwzOutputLimit = 0;
	}

	~OUTPUT_MONITOR( )
	{
		if( ppwzOutput )
		{
			for( DWORD iIndex = 0; iIndex < cpwzOutput; iIndex++ )
			{
				if( ppwzOutput[iIndex] )
				{
					free( (void *) ppwzOutput[iIndex] );
					ppwzOutput[iIndex] = NULL;
				}
			}

			free( (void *) ppwzOutput );
			ppwzOutput = NULL;
		}
	}

    STDMETHOD(QueryInterface)(
        __in REFIID InterfaceId,
        __out PVOID* Interface
		)
	{ 
		if( Interface == NULL )
		{
			return( E_POINTER );
		}

		if( IsEqualIID( InterfaceId, IID_IUnknown ) || IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacksWide)) )
		{
			*Interface = this;
			return( S_OK );
		}
		else
		{
			*Interface = NULL;
			return( E_NOINTERFACE );
		}
	}

    STDMETHOD_(ULONG, AddRef)(
        ) 
	{
		return (ULONG) ::InterlockedIncrement(&lRefCount);
	}

    STDMETHOD_(ULONG, Release)(
        )
	{
		ULONG lActiveRefCount = ::InterlockedDecrement(&lRefCount);

		if ( lActiveRefCount == 0)
		{
			delete this;
			return 0;
		}

		return lActiveRefCount;
	}

    STDMETHOD(Output)(
	   THIS_
        __in ULONG /* Mask */,
        __in PCWSTR Text
        )
	{
		if( (cpwzOutput+1) >= cpwzOutputLimit )
		{
			LPCWSTR *  ppwzNewOutput = (LPCWSTR *) realloc( ppwzOutput, sizeof( LPCWSTR ) * (cpwzOutputLimit+16) );

			if (ppwzNewOutput == NULL)
				return 0;
			
			cpwzOutputLimit += 16;
			ppwzOutput =ppwzNewOutput;

			for( DWORD iEntry = cpwzOutput; iEntry < cpwzOutputLimit; iEntry++ )
			{
				ppwzOutput[iEntry] = NULL;
			}
		}

		ppwzOutput[cpwzOutput++] = _wcsdup( Text );

		return( 0 );
	}

	LPCWSTR * GetOutputText( )
	{
		return( ppwzOutput );
	}

	DWORD GetOutputTextCount( )
	{
		return( cpwzOutput );
	}

private:
	LONG lRefCount;
	LPCWSTR *ppwzOutput;
	DWORD cpwzOutput;
	DWORD cpwzOutputLimit;
};




/// Functions for managing the global resources of !exploitable
bool LoadCustomExcludeList(HMODULE hModule);
void UnloadCustomExcludeList();


#ifdef DEBUGGER_MODULE



PCSTR EXCLUDED_SYMBOLS[] = 
{
	"apvrf!*",
	"apvrf",
    "ntdll*!dbgbreakpoint",
    "ntdll*!dbguiremotebreakin",
	"ntdll*!_eh4_callfilterfunc",
	"ntdll*!_except_handler4",
	"ntdll*!executehandler2",
	"ntdll*!executehandler",
	"ntdll*!kifastsystemcallret",
	"ntdll*!kiuserexceptiondispatcher",
	"ntdll*!rtl*exception*",
	"ntdll*!rtl*heap*",
	"ntdll*!rtl*failure*",
	"ntdll*!zwwaitformultipleobjects",
	"msvcrt!free",
	"msvcrt!*alloc",
	"kernel32!werp*",
	"kernel32!unhandledexceptionfilter",
	"kernel32!*raiseexception*",
	"kernel32!waitformultipleobjects*",
	"kernel32!heapfree",
	"kernel32!kebugcheck*",
	"clrstub*",
	"vrfcore!*",
	"vrfcore"
	"vfbasics!*",
	"vfbasics",
	"verifier!*",
	"verifier",
	"mscorwks",
	NULL
};


///
// Internal Functions
///

bool IsSymbolExcluded( PCSTR pszSymbol );

#endif 



#define ROL(x,n) (((x)<<(n))|((x)>>(32-(n))))

void CalculateStackHash( const DEBUGGER_CONTROLS& objDebugger, 
					ULONG cStackFrames, 
					__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames, 
					HASHING_MODE eHashMode,
					_Out_writes_opt_(cStackFrames)  bool* pfUnknownStackFrames,
					_Out_writes_opt_(cStackFrames)  bool* pfExcludedStackFrames, 
					__out_opt bool *pfStackContainsUnknownSymbols, 
					__out ULONG* pdwMajorHash, 
					__out ULONG* pdwMinorHash );

void CalculateStackHash( const DEBUGGER_CONTROLS& objDebugger, ULONG cStackFrames, __in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames,HASHING_MODE eHashMode,  __out ULONG* pdwMajorHash, __out ULONG* pdwMinorHash );

void DetermineUnknownandExcludedFrames(const DEBUGGER_CONTROLS& objDebugger, ULONG cStackFrames, __in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames, _Out_writes_opt_(cStackFrames)  bool* pfUnknownStackFrames,_Out_writes_opt_(cStackFrames)  bool* pfExcludedStackFrames,  __out_opt bool *pfStackContainsUnknownSymbols );
void CalculateHashCustomV1(const DEBUGGER_CONTROLS& objDebugger,ULONG cStackFrames,__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames,   __inout ULONG* pdwMajorHash, __inout ULONG* pdwMinorHash );
void CalculateHashCustomV2(const DEBUGGER_CONTROLS& objDebugger,ULONG cStackFrames,__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames,   __inout ULONG* pdwMajorHash, __inout ULONG* pdwMinorHash );
void CalculateHashSHA256(const DEBUGGER_CONTROLS& objDebugger,ULONG cStackFrames,__in_ecount(cStackFrames) DEBUG_STACK_FRAME* pStackFrames ,__inout ULONG* pdwMajorHash, __inout ULONG* pdwMinorHash );

bool GetSymbolValue( const DEBUGGER_CONTROLS& objDebugger, ULONG iStackFrame, PCSTR pszSymbol, PULONG64 pqwValue );
bool GetProcessorFlagByName( const DEBUGGER_CONTROLS &objControls, PCWSTR pwzFlage );
