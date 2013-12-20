//
// metainstructions.h
//
// Meta Instruction Definitions for the MSEC Debugging Extensions Meta-Disassembler
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

#include <set>
#include <list>

////
//  Each metainstruction is assigned an Instruction Class. This class is then used by subsequent rules to 
//  evaluate the security implications.
//
//  Rules which make assumptions should be documented here.
//
//  ---
//  GatherTaintInformation():
//
//  The lightweight taint tracking gather rule has some assumptions built into it based on the Instruction Class of the
//  metainstruction.
//
//  These assumptions are:
//
//  UNKNOWN_INSTRUCTION: No taint will be calculated or cleared, the instruction is a functional NOP
//  POP: Destination operands are assigned taint from the stack emulation in the order they are defined in the INSTRUCTION_INFO, implicit destinations first, then explicit destinations
//  PUSH: Taint is assigned to the stack emulation for source operands in the order they are defined in the INSTRUCTION_INFO, explicit sources first, then explicit sources
//  DATA_EXCHANGE: Not currently implemented
//  All Others: Taint is assigned to destination registers if any of the source, destination pointer, or passed or returned values are tainted. Taint is cleared in destination registers if all sources are untainted.
//
//  Passed or returned values should only be used in instructions which end the basic block.
//
//  ---
//
//	IsTaintedDataUsedToDetermineBranchSelection():
//
//  BRANCH: The assumption is that implicit registers (and only implicit registers) are used to determine whether or not a branch is taken, but not the branch address. 
//
//  ---
//
//  IsTaintedDataUsedToDetermineBranchTarget():
//
//	BRANCH: The assumption is that explicit registers (and only explicit registers) are used to determine the branch target
//

typedef enum _INSTRUCTION_CLASS
{
	UNKNOWN_INSTRUCTION = 0,
	BRANCH,
	RETURN,
	UNPREDICTABLE_CONDITIONAL_EXECUTION,
	INTERRUPT,
	DATA_MOVE,
	DATA_EXCHANGE,
	BLOCK_DATA_MOVE,
	STACK_PUSH,
	STACK_POP,
	CALCULATION,
	NOOP,
	NONDISASSEMBLE_INSTRUCTION
} INSTRUCTION_CLASS;


typedef struct _OPERAND
{
	bool operator<( const _OPERAND& rhs ) const
	{
		if( !pwzOperand )
		{
			return( false );
		}
		else if( pwzOperand && !rhs.pwzOperand )
		{
			return( true );
		}

		if( rhs.cchOperand < cchOperand )
		{
			return( false );
		}

		if( rhs.cchOperand > cchOperand )
		{
			return( true );
		}

		return( wcsncmp( pwzOperand, rhs.pwzOperand, cchOperand ) < 0 );
	}

	PCWSTR pwzOperand;
	size_t cchOperand;
} OPERAND;

typedef std::set<OPERAND> OPERAND_SET;

typedef std::list<OPERAND_SET> OPERAND_SET_LIST;

// Macro definitions for OPERAND and OPERAND lists
#define OPERAND_ENTRY( x )	{ x, (sizeof( x ) / sizeof( WCHAR )) - 1 }
#define END_OPERAND_LIST	{ NULL, 0 }

struct _INSTRUCTION_INFO;

typedef struct _INSTRUCTION
{
	_INSTRUCTION()
	{

		offAddress = 0xffffffffffffffff;
		offNextInstruction = 0xffffffffffffffff;
		eClass = UNKNOWN_INSTRUCTION;
		fFlagsRegisterModified = false;
		fFlagsRegisterValid = false;		
		pInstructionInfo = NULL;
		pwzInstructionBuffer = NULL;
		pwzMnemonic = NULL;
		pwzArguments = NULL;
		pwzOpCode = NULL;
		pwzAddress = NULL;
	}

	virtual ~_INSTRUCTION()
	{
		// Clear the source and destination information
		setSourceRegisters.clear();
		setDestinationRegisters.clear();
		setDestinationPointerRegisters.clear();
		setPassedOrReturnedRegisters.clear();
		setTaintedInputRegisters.clear();
		setExplicitRegisters.clear();
		setCompoundRegisters.clear();

		if( pwzInstructionBuffer != NULL )
		{
			delete[] pwzInstructionBuffer;
			pwzInstructionBuffer = NULL;
			pwzMnemonic = NULL;
			pwzArguments = NULL;
			pwzOpCode = NULL;
			pwzAddress = NULL;
		}

		pInstructionInfo = NULL;
	}

	ULONG64					offAddress;
	ULONG64					offNextInstruction;
	INSTRUCTION_CLASS		eClass;
	const _INSTRUCTION_INFO	*pInstructionInfo;
	PCWSTR					pwzInstructionBuffer;
	PCWSTR					pwzMnemonic;
	PCWSTR					pwzArguments;
	PCWSTR					pwzOpCode;
	PCWSTR					pwzAddress;
	bool					fFlagsRegisterModified;
	bool					fFlagsRegisterValid;
	OPERAND_SET				setSourceRegisters;
	OPERAND_SET				setDestinationRegisters;
	OPERAND_SET				setDestinationPointerRegisters;
	OPERAND_SET				setPassedOrReturnedRegisters;
	OPERAND_SET				setTaintedInputRegisters;
	OPERAND_SET				setExplicitRegisters;
	OPERAND_SET				setCompoundRegisters;
} INSTRUCTION;

typedef std::list<INSTRUCTION *> INSTRUCTION_LIST;
