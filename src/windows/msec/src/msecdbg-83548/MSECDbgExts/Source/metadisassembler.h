//
// metadisassembler.h
//
// Definitions for the MSEC Debugging Extensions Meta-Disassembler
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

#pragma once

#include "debugger.h"
#include "metainstructions.h"

///
// Public Disassembly Constants and Enums 
///
///

/// Taint Tracking Mode Enum
///
typedef enum _TAINT_TRACKING_MODE
{
	SET_TAINT = 0,
	CLEAR_TAINT = 1
} TAINT_TRACKING_MODE;

/// Constant Definitions for implied virtual registers
///
/// These include the contents of the stack, and the flag registers.
///
// Important:
//    STACK_CONTENTS should never be explicitly set as a destination register in an instruction definition,
//    because it is set by the light-weight stack emulation in the taint tracking. It can be validly used in
//    other register sets
//
// Note:
//	  The Flags logical registers should be aliased to the logical flags register as supported by individual processors
//
#define STACK_CONTENTS			L"StackContents"
#define ZERO_FLAG				L"ZeroFlag"
#define CARRY_FLAG				L"CarryFlag"
#define OVERFLOW_FLAG			L"OverflowFlag"
#define PARITY_FLAG				L"ParityFlag"
#define SIGN_FLAG				L"SignFlag"
#define AUX_FLAG				L"AuxFlag"
#define FLAGS_REGISTER			L"Flags"

/// 
/// Operand encoding information for the MetaDisassembler
///
/// This provides information as to the expected operands for an instruction, as well as 
/// additional logical information about the operands, including, for example, whether or not
/// what would normally be the "destination" is actually affected by the operation
///
typedef enum _INSTRUCTION_OPERANDS
{
	NO_OPERANDS = 0,
	SOURCE_REGISTER = 1,
	SOURCE_POINTER = 2,
	SOURCE_OPERANDS = 3,
	DEST_REGISTER = 4,
	DEST_POINTER = 8,
	DEST_OPERANDS = 12,
	DEST_OPERAND_IS_IMPLIED_SOURCE = 16,
	DEST_OPERAND_IS_UNAFFECTED = 32,
	OPERAND_ORDER_REVERSED = 64,
	DUAL_INITIAL_OPERANDS = 128,
	SOURCE_OPERANDS_ONLY = SOURCE_OPERANDS,
	DEST_OPERANDS_ONLY = DEST_OPERANDS,
	COMBO_OPERANDS = SOURCE_OPERANDS | DEST_OPERANDS,
	COMBO_OPERANDS_REGISTERS_ONLY = SOURCE_REGISTER | DEST_REGISTER,
	COMBO_OPERANDS_POINTERS_ONLY = SOURCE_POINTER | DEST_POINTER
} INSTRUCTION_OPERANDS;

#define HAS_SOURCE_OPERANDS(x)					( (x & SOURCE_OPERANDS) != 0 )
#define HAS_SOURCE_REGISTERS(x)					( (x & SOURCE_REGISTER) != 0 )
#define HAS_SOURCE_POINTER(x)					( (x & SOURCE_POINTER) != 0 )
#define HAS_DEST_OPERANDS(x)					( (x & DEST_OPERANDS) != 0 )
#define HAS_DEST_REGISTERS(x)					( (x & DEST_REGISTER) != 0 )
#define HAS_DEST_POINTER(x)						( (x & DEST_POINTER) != 0 )
#define HAS_REGISTERS_ONLY(x)					( (x & ~COMBO_OPERANDS_REGISTERS_ONLY) == 0 )
#define HAS_POINTERS_ONLY(x)					( (x & ~COMBO_OPERANDS_POINTERS_ONLY) == 0 )
#define HAS_DEST_OPERAND_AS_IMPLIED_SOURCE(x)	( (x & DEST_OPERAND_IS_IMPLIED_SOURCE) != 0 )
#define HAS_DEST_OPERAND_AS_UNAFFECTED(x)		( (x & DEST_OPERAND_IS_UNAFFECTED) != 0 )
#define HAS_OPERAND_ORDER_REVERSED(x)			( (x & OPERAND_ORDER_REVERSED) != 0)
#define HAS_DUAL_INITIAL_OPERANDS(x)			( (x & DUAL_INITIAL_OPERANDS) != 0)

///
/// The Instruction Classification for Metadisassembly
///
/// Important Note:
///
/// There are four types of implicit registers for the Instruction Information
///
/// Source Registers: The contents of these registers is used to determine the instruction outcome
/// Destination Registers: These values are set based on the instruction
/// Destination Pointer Registers: These are registers that point to the results. They are effectively additional source registers in taint tracking.
/// Passed or Returned Registers: These are values that are either passed or returned by the instruction. These are effectively source registers,
///                               and should only be set in instructions which end the basic block
///
/// By separating how the values are used, we are able to develop more intelligent rules.
typedef void (*ANALYSIS_OVERRIDE_PROC) (INSTRUCTION *  );

#define MAX_ANALYSIS_FUNCTIONS		8
#define MAX_REGISTER_DECLARATIONS	32

typedef struct _INSTRUCTION_INFO
{
	PCWSTR					pwzMnemonic;
	DWORD					cchMnemonic;
	bool					fExactMatch;
	INSTRUCTION_CLASS		eClassification;
	INSTRUCTION_OPERANDS	eOperandClassification;
	ANALYSIS_OVERRIDE_PROC	arrAnalysisOverrideFunctions[MAX_ANALYSIS_FUNCTIONS+1];
	OPERAND					arrImplicitSourceRegisters[MAX_REGISTER_DECLARATIONS+1];
	OPERAND					arrImplicitDestinationRegisters[MAX_REGISTER_DECLARATIONS+1];
	OPERAND					arrImplicitDestinationPointerRegisters[MAX_REGISTER_DECLARATIONS+1];
	OPERAND					arrImplicitPassedOrReturnedRegisters[MAX_REGISTER_DECLARATIONS+1];
} INSTRUCTION_INFO;

#ifdef METADISASSEMBLER_MODULE

/// Syntactic sugar for the instruction information definitions
#define BEGIN_INSTRUCTION							,{
#define BEGIN_FIRST_INSTRUCTION						{
#define MNEMONIC( x )								x, (sizeof( x ) / sizeof( WCHAR )) - 1, false
#define EXACT_MNEMONIC( x )							x, (sizeof( x ) / sizeof( WCHAR )) - 1, true
#define INSTRUCTION_CLASSIFICATION					,
#define OPERAND_ENCODING							,(INSTRUCTION_OPERANDS)(
#define ANALYSIS_FUNCTIONS							), {
#define NO_ANALYSIS_FUNCTIONS						), { END_FUNCTION_LIST
#define END_FUNCTION_LIST							NULL }
#define NO_IMPLICIT_OPERANDS						NO_IMPLICIT_SOURCE_REGISTERS NO_IMPLICIT_DESTINATION_REGISTERS NO_IMPLICIT_DESTINATION_POINTER_REGISTERS NO_IMPLICIT_PASSED_OR_RETURNED_REGISTERS
#define IMPLICIT_SOURCE_REGISTERS					,{
#define NO_IMPLICIT_SOURCE_REGISTERS				,{ END_OPERAND_LIST
#define IMPLICIT_DESTINATION_REGISTERS				},{
#define NO_IMPLICIT_DESTINATION_REGISTERS			},{ END_OPERAND_LIST
#define IMPLICIT_DESTINATION_POINTER_REGISTERS		},{
#define NO_IMPLICIT_DESTINATION_POINTER_REGISTERS	},{ END_OPERAND_LIST
#define IMPLICIT_PASSED_OR_RETURNED_REGISTERS		},{
#define NO_IMPLICIT_PASSED_OR_RETURNED_REGISTERS	},{ END_OPERAND_LIST
#define END_INSTRUCTION								} }

///
// Excluded operands by processor type
///

PCWSTR X64_X86_EXCLUDED_OPERANDS[] = { L"ptr", L"byte", L"word", L"dword", L"qword", NULL };
PCWSTR ARM_EXCLUDED_OPERANDS[] = { NULL };

///
// Processor Analysis Override Functions
///
void ReflexiveCancellationAnalysisOverride( INSTRUCTION *pInstruction );
void ARMImplicitReturnAnalysisOverride( INSTRUCTION *pInstruction );
void ARMImplicitBranchAnalysisOverride( INSTRUCTION *pInstruction );
void ARMBlockMoveAnalysisOverride( INSTRUCTION *pInstruction );

#endif

///
// Public Disassembly Functions
///

bool Disassemble( const DEBUGGER_CONTROLS &objControls, ULONG64 offAddress, ULONG dwProcessor, bool fFlagsRegisterValid, const OPERAND_SET& setProcessorFlags, INSTRUCTION *pInstruction );

const OPERAND * GetRegisterAliases( ULONG dwProcessor, PCWSTR pwzRegister, size_t cchRegister, TAINT_TRACKING_MODE eMode );

void AddOperandToSet( PCWSTR pwzOperandName, OPERAND_SET *psetOperands );

void AddOperandToSet( PCWSTR pwzOperandName, size_t cchOperandName, OPERAND_SET *psetOperands );

void AddRegisterRangeToSet( PCWSTR pwzFirstOperand, size_t cchFirstOperand, PCWSTR pwzSecondOperand, size_t cchSecondOperand, OPERAND_SET * psetOperands );

bool DoesSetContainOperand( PCWSTR pwzOperandName, const OPERAND_SET &setOperands );

const OPERAND * GetOperandsInPushOrder( DWORD dwProcessor, const OPERAND_SET &setOperands );

const OPERAND * GetOperandsInPopOrder( DWORD dwProcessor, const OPERAND_SET &setOperands );

#ifdef METADISASSEMBLER_MODULE

///
// Internal Disassembly Functions
///

bool IsStringInSet( __in PCWSTR pwzString, size_t cchString, __in PCWSTR *ppwzSet );

bool DoesInstructionModifyFlags( const INSTRUCTION& objInstruction );

void ParseDisassemblyFieldInPlace( __in PWSTR *ppwzIndex, __in_opt PCWSTR *ppwzValidPrefixes );

bool FindNextOperand( __in PCWSTR pwzOperand, __in PCWSTR pwzDelimiters, __out PCWSTR pwzNextOperand, __out size_t * pcchOperand, __out WCHAR * pchDelimiter );

void Findx86_x64Operands( INSTRUCTION *pInstruction, const INSTRUCTION_INFO& objInstructionInfo, PCWSTR *ppwzRegisters );

void FindARMOperands( INSTRUCTION *pInstruction, const INSTRUCTION_INFO& objInstructionInfo, PCWSTR *ppwzRegisters );

void ParseARMMnemonic( INSTRUCTION *pInstruction, const OPERAND_SET& setProcessorFlags  );

bool ClassifyX86Instruction( INSTRUCTION *pInstruction );

bool ClassifyX64Instruction( INSTRUCTION *pInstruction );

bool ClassifyARMInstruction( INSTRUCTION *pInstruction, const OPERAND_SET& setProcessorFlags );

const OPERAND * GetSortedOperandsList( const OPERAND_SET &sourceOperands, PCWSTR arrOrder[] );
#endif
