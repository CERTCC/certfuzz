//
// metadisassembler.cpp
//
// The MSEC Debugger Extension Metadisassembler
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


#define METADISASSEMBLER_MODULE
#include "stdafx.h"
#include "metadisassembler.h"
#include "metadisassembler_x86.h"
#include "metadisassembler_x64.h"
#include "metadisassembler_ARM.h"

///
/// Is the string in the specified set
bool
IsStringInSet( __in PCWSTR pwzString, size_t cchString, __in PCWSTR *ppwzSet )
{
	while( *ppwzSet != NULL )
	{
		if( wcsncmp( pwzString, *ppwzSet, cchString ) == 0 )
		{
			return( true );
		}

		ppwzSet++;
	}

	return( false );
}

///
/// Get any register aliases for the register passed in. This is heavily used in the x86/x64 meta-disassembly, to map ah, al, ax, eax, and rax together, for example
const OPERAND *
GetRegisterAliases( ULONG dwProcessor, PCWSTR pwzRegister, size_t cchRegister, TAINT_TRACKING_MODE eMode )
{
	OPERAND *pRegisterAliases = NULL;

	switch( dwProcessor )
	{
		case IMAGE_FILE_MACHINE_I386:
			if( eMode == SET_TAINT )
			{
				pRegisterAliases = X86_REGISTER_TAINT_ALIASES;
			}
			else if( eMode == CLEAR_TAINT )
			{
				pRegisterAliases = X86_REGISTER_CLEAR_ALIASES;
			}
			else
			{
				return( NULL );
			}
			break;

		case IMAGE_FILE_MACHINE_ARM:
		case IMAGE_FILE_MACHINE_THUMB:
		case IMAGE_FILE_MACHINE_ARMNT:
			return( NULL );

		case IMAGE_FILE_MACHINE_AMD64:
			if( eMode == SET_TAINT )
			{
				pRegisterAliases = X64_REGISTER_TAINT_ALIASES;
			}
			else if( eMode == CLEAR_TAINT )
			{
				pRegisterAliases = X64_REGISTER_CLEAR_ALIASES;
			}
			else
			{
				return( NULL );
			}
			break;

		default:
			return( NULL );
	}

	// Search through the alias list	
	while( pRegisterAliases->pwzOperand != NULL )
	{
		OPERAND *pComparison = pRegisterAliases;

		while( pComparison->pwzOperand != NULL )
		{
			if( (cchRegister == pComparison->cchOperand) &&
				(wcsncmp( pwzRegister, pComparison->pwzOperand, cchRegister ) == 0) )
			{
				return( pRegisterAliases );
			}
			else
			{
				// Skip to the end of this list, because we only compare the first registers in each list
				while( pComparison->pwzOperand != NULL )
				{
					pComparison++;
				}
			}
		}

		pRegisterAliases = pComparison + 1;
	}

	return( NULL );
}

///
/// Disassemble the instruction at the given address, creating an instruction object
///
bool
Disassemble( const DEBUGGER_CONTROLS &objControls, ULONG64 offAddress, ULONG dwProcessor, bool fFlagsRegisterValid, const OPERAND_SET& setProcessorFlags, INSTRUCTION *pInstruction )
{
	// Disassemble the instruction
	ULONG cchInstruction;
	ULONG dwAssemblyOptions;
	HRESULT dwResult;

	// For ARM/THUMB processors, mask off the lowest address bit
	if( (dwProcessor == IMAGE_FILE_MACHINE_ARM) || (dwProcessor == IMAGE_FILE_MACHINE_THUMB) || (dwProcessor == IMAGE_FILE_MACHINE_ARMNT) )
	{
		offAddress = offAddress & ~0x1;
	}

	objControls.pDebugControl->GetAssemblyOptions( &dwAssemblyOptions );
	objControls.pDebugControl->SetAssemblyOptions( dwAssemblyOptions & ~(DEBUG_ASMOPT_NO_CODE_BYTES | DEBUG_ASMOPT_SOURCE_LINE_NUMBER) );
	objControls.pDebugControl->DisassembleWide( offAddress, 0, NULL, 0, &cchInstruction, &pInstruction->offNextInstruction );
	pInstruction->pwzInstructionBuffer = new WCHAR[cchInstruction + 1];

	if( pInstruction->pwzInstructionBuffer == NULL )
	{
		return( false );
	}

	dwResult = objControls.pDebugControl->DisassembleWide( offAddress, 0, (PWSTR) pInstruction->pwzInstructionBuffer, cchInstruction + 1, NULL, &pInstruction->offNextInstruction );
	objControls.pDebugControl->SetAssemblyOptions( dwAssemblyOptions );

	if( dwResult != S_OK )
	{
		return( false );
	}
	else
	{
		pInstruction->offAddress = offAddress;
		_wcslwr_s( (PWSTR) pInstruction->pwzInstructionBuffer, cchInstruction );
	}

	// Check for disassembly errors that would cause infinite loops, this is usually due to a mismatch
	// between the debugger machine mode and the process machine mode (x86 versus x64)
	if( pInstruction->offAddress == pInstruction->offNextInstruction )
	{
		return( false );
	}

	// Check for a mismatch in the disassembly
	if( wcsstr( pInstruction->pwzInstructionBuffer, L"disassembly not possible" ) != NULL )
	{
		return( false );
	}

	// Store the instruction flags information
	pInstruction->fFlagsRegisterValid = fFlagsRegisterValid;

	// Parse the fields for the continued processing
	PWSTR pwzIndex = (PWSTR) pInstruction->pwzInstructionBuffer;
	pInstruction->pwzAddress = (PCWSTR) pwzIndex ;
	ParseDisassemblyFieldInPlace( &pwzIndex, NULL );
	pInstruction->pwzOpCode = (PCWSTR) pwzIndex;
	ParseDisassemblyFieldInPlace( &pwzIndex, NULL );
	pInstruction->pwzMnemonic = (PCWSTR) pwzIndex;

	switch( dwProcessor )
	{
		case IMAGE_FILE_MACHINE_I386:
			{
				ParseDisassemblyFieldInPlace( &pwzIndex, X86_MNEMONIC_PREFIXES );
			}
			break;

		case IMAGE_FILE_MACHINE_AMD64:
			{
				ParseDisassemblyFieldInPlace( &pwzIndex, X64_MNEMONIC_PREFIXES );
			}
			break;

		case IMAGE_FILE_MACHINE_ARM:
		case IMAGE_FILE_MACHINE_THUMB:
		case IMAGE_FILE_MACHINE_ARMNT:
			{
				ParseDisassemblyFieldInPlace( &pwzIndex, ARM_MNEMONIC_PREFIXES );
			}
			break;

		default:
			return( false );
	}
	pInstruction->pwzArguments = (PCWSTR) pwzIndex;
	
	if( pInstruction->pwzArguments != NULL )
	{
		size_t cchArguments = wcslen( pInstruction->pwzArguments );

		if( cchArguments > 0 )
		{
			if( pInstruction->pwzArguments[cchArguments - 1] == '\n' )
			{
				((PWSTR) pInstruction->pwzArguments)[cchArguments - 1] = '\0';
			}
		}
	}

	// Check for invalid op codes or menmonics, that indicate a disassembly failure
	if( *pInstruction->pwzMnemonic == '?' )
	{
		return( false );
	}

	if( *pInstruction->pwzOpCode == '<' )
	{
		return( false );
	}

	// Classify the instruction
	//
	// Note that we don't consider our inability to match an instruction to be an error here, we'll continue with it
	// until we find an error in the actual disassembly routines (above)
	switch( dwProcessor )
	{
		case IMAGE_FILE_MACHINE_I386:
			{
				ClassifyX86Instruction( pInstruction );
				return( true );
			}

		case IMAGE_FILE_MACHINE_AMD64:
			{
				ClassifyX64Instruction( pInstruction );
				return( true );
			}

		case IMAGE_FILE_MACHINE_ARM:
		case IMAGE_FILE_MACHINE_THUMB:
		case IMAGE_FILE_MACHINE_ARMNT:
			{
				ClassifyARMInstruction( pInstruction, setProcessorFlags );
				return( true );
			}

		default:
			return( false );
	}
}

///
/// Parse out a disassembly field in place, replacing spaces with null terminators
void
ParseDisassemblyFieldInPlace( __in PWSTR *ppwzIndex, __in_opt PCWSTR *ppwzValidPrefixes )
{
	PWSTR pwzStart = *ppwzIndex;
	bool fInField = true;

	while(  **ppwzIndex != '\0' )
	{
		if( **ppwzIndex == ' ' )
		{
			if( ppwzValidPrefixes != NULL )
			{
				if( !IsStringInSet( pwzStart, *ppwzIndex - pwzStart, ppwzValidPrefixes ) )
				{
					**ppwzIndex = '\0';
					fInField = false;
				}
			}
			else
			{
				**ppwzIndex = '\0';
				fInField = false;
			}
		}
		else
		{
			if( !fInField )
			{
				return;
			}
		}

		*ppwzIndex += 1;
	}
}

///
/// Determine whether or not the specified instruction can affect the flags
///
bool
DoesInstructionModifyFlags( const INSTRUCTION& objInstruction )
{
	return( (objInstruction.eClass != NOOP) &&
			((objInstruction.eClass == UNKNOWN_INSTRUCTION) ||
			DoesSetContainOperand( FLAGS_REGISTER, objInstruction.setDestinationRegisters ) ||
			DoesSetContainOperand( ZERO_FLAG, objInstruction.setDestinationRegisters ) ||
			DoesSetContainOperand( CARRY_FLAG, objInstruction.setDestinationRegisters ) ||
			DoesSetContainOperand( OVERFLOW_FLAG, objInstruction.setDestinationRegisters ) ||
			DoesSetContainOperand( PARITY_FLAG, objInstruction.setDestinationRegisters ) ||
			DoesSetContainOperand( SIGN_FLAG, objInstruction.setDestinationRegisters ) ||
			DoesSetContainOperand( AUX_FLAG, objInstruction.setDestinationRegisters ) ));
}


///
/// Find the next operand, and the delimiter that triggered it. This function returns false if the string is empty, otherwise, it returns true.
///
bool
FindNextOperand( __in PCWSTR pwzOperand, __in PCWSTR pwzDelimiters, __out PCWSTR *ppwzNextOperand, __out size_t * pcchOperand, __out WCHAR * pchDelimiter )
{
	if( *pwzOperand == '\0' )
	{
		*ppwzNextOperand = pwzOperand;
		*pcchOperand = 0;
		*pchDelimiter = *pwzOperand;
		return( false );
	}

	*pcchOperand = wcscspn( pwzOperand, pwzDelimiters );
	*pchDelimiter = *(pwzOperand + *pcchOperand);

	if( *pchDelimiter != '\0' )
	{
		*ppwzNextOperand = pwzOperand + *pcchOperand + 1;
	}
	else
	{
		*ppwzNextOperand = pwzOperand + *pcchOperand;
	}

	return( true );
}

///
/// Find the operands for the instruction for x86 and x64
///
void
Findx86_x64Operands( INSTRUCTION *pInstruction, const INSTRUCTION_INFO& objInstructionInfo, PCWSTR *ppwzRegisters )
{
	// Set the implicit operands
	const OPERAND *pOperands = (const OPERAND *) objInstructionInfo.arrImplicitSourceRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setSourceRegisters.insert( *pOperands );
		pOperands++;
	}

	pOperands = (const OPERAND *) objInstructionInfo.arrImplicitDestinationRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setDestinationRegisters.insert( *pOperands );
		pOperands++;
	}

	pOperands = (const OPERAND *) objInstructionInfo.arrImplicitDestinationPointerRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setDestinationPointerRegisters.insert( *pOperands );
		pOperands++;
	}

	pOperands = (const OPERAND *) objInstructionInfo.arrImplicitPassedOrReturnedRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setPassedOrReturnedRegisters.insert( *pOperands );
		pOperands++;
	}

	if( objInstructionInfo.eOperandClassification == NO_OPERANDS )
	{
		return;
	}

	// Set our search rules. Note that we have some special case code to handle EBP and ESP references, because we 
	// want to be able to track those. To do that, we end up with special monitoring flags and an extra backwards looking
	// operand pointer.
	bool fInSource = !HAS_DEST_OPERANDS( objInstructionInfo.eOperandClassification ) || HAS_OPERAND_ORDER_REVERSED( objInstructionInfo.eOperandClassification );
	bool fInIndirectReference = false;
	bool fInMonitoredPointerReference = false;
	PCWSTR pwzMonitoredPointerOperand = NULL;

	PCWSTR pwzOperand = pInstruction->pwzArguments;
	PCWSTR pwzNextOperand = NULL;
	size_t cchOperand;
	WCHAR chDelimiter;

	while( FindNextOperand( pwzOperand, L"[], :+-*", &pwzNextOperand, &cchOperand, &chDelimiter ) )
	{
		// Prepare for the next iteration
		PCWSTR pwzCurrentOperand = pwzOperand;
		pwzOperand = pwzNextOperand;

		// Cache state information for this iteration
		bool fWasInIndirectReference = fInIndirectReference;
		bool fWasInSource = fInSource;

		// Check the delimiter we found, because it can change things
		switch( chDelimiter )
		{
			case ',':
				{
					if( HAS_OPERAND_ORDER_REVERSED( objInstructionInfo.eOperandClassification ) )
					{
						fInSource = !HAS_DEST_OPERANDS( objInstructionInfo.eOperandClassification );
					}
					else
					{
						fInSource = HAS_SOURCE_OPERANDS( objInstructionInfo.eOperandClassification );
					}
				}
				break;

			case '[':
				fInIndirectReference = true;
				break;

			case ']':
				fInIndirectReference = false;

				if( fInMonitoredPointerReference )
				{
					OPERAND objOperand;
					
					objOperand.pwzOperand = pwzMonitoredPointerOperand;
					objOperand.cchOperand = (pwzCurrentOperand - pwzMonitoredPointerOperand) + cchOperand;
					
					if( fWasInSource )
					{
						pInstruction->setSourceRegisters.insert( objOperand );
					}
					else
					{
						// If the destination operand is flagged as being unaffected by the instruction, don't add it
						// to the destination register set
						if( !HAS_DEST_OPERAND_AS_UNAFFECTED( objInstructionInfo.eOperandClassification ) )
						{
							pInstruction->setDestinationRegisters.insert( objOperand );
						}

						// If the destination is flagged as being an implied source register, we add it to the 
						// implied source registers as well
						if( HAS_DEST_OPERAND_AS_IMPLIED_SOURCE( objInstructionInfo.eOperandClassification ) )
						{
							pInstruction->setSourceRegisters.insert( objOperand );
						}
					}

					// We additionally tag registers that were explicitly defined, rather than implicitly defined
					pInstruction->setExplicitRegisters.insert( objOperand );

					// And we tag compound registers because we want to be able to invalidate them 
					// if the indexing registers are changed
					if( wcscspn( objOperand.pwzOperand, L", :+-*" ) < objOperand.cchOperand )
					{
						pInstruction->setCompoundRegisters.insert( objOperand );
					}

					fInMonitoredPointerReference = false;
					pwzMonitoredPointerOperand = NULL;

					// And we're done, since we've added the pointer reference as a logical register
					continue;
				}
				break;

			case ':':
				continue;
		}

		// Continue if we don't have any actual operand
		if( cchOperand == 0 )
		{
			continue;
		}

		// Otherwise, we have to check the operand found to see if we are going to add it to the list
		if( IsStringInSet( pwzCurrentOperand, cchOperand, X64_X86_EXCLUDED_OPERANDS ) )
		{
			fInMonitoredPointerReference = false;
			pwzMonitoredPointerOperand = NULL;
			continue;
		}

		/// Skip the numbers
		if( iswdigit( *pwzCurrentOperand ) )
		{
			continue;
		}

		// Skip items in parentheses 
		if( *pwzCurrentOperand == '(' )
		{
			fInMonitoredPointerReference = false;
			pwzMonitoredPointerOperand = NULL;
			continue;
		}

		// Skip anything that isn't a register
		if( !IsStringInSet( pwzCurrentOperand, cchOperand, ppwzRegisters ) )
		{
			continue;
		}

		// Check to see if this is a monitored register (for local variable references)
		if( fInIndirectReference &&
			(pwzCurrentOperand[cchOperand-1] == 'p') && (pwzMonitoredPointerOperand == NULL) &&
			((chDelimiter == '+') || (chDelimiter == '-')) )
		{
			fInMonitoredPointerReference = true;
			pwzMonitoredPointerOperand = pwzCurrentOperand;
		}
		else
		{
			fInMonitoredPointerReference = false;
			pwzMonitoredPointerOperand = NULL;
		}

		// Add the register
		OPERAND objOperand;
		
		objOperand.pwzOperand = pwzCurrentOperand;
		objOperand.cchOperand = cchOperand;

		if( fWasInSource )
		{
			pInstruction->setSourceRegisters.insert( objOperand );
		}
		else
		{
			// If the destination operand is flagged as being unaffected by the instruction, don't add it
			// to the destination register set
			if( !HAS_DEST_OPERAND_AS_UNAFFECTED( objInstructionInfo.eOperandClassification ) )
			{
				if( fWasInIndirectReference || !HAS_DEST_REGISTERS( objInstructionInfo.eOperandClassification) )
				{
					pInstruction->setDestinationPointerRegisters.insert( objOperand );
				}
				else
				{
					pInstruction->setDestinationRegisters.insert( objOperand );
				}
			}

			// If the destination is flagged as being an implied source register, we add it to the 
			// implied source registers as well
			if( HAS_DEST_OPERAND_AS_IMPLIED_SOURCE( objInstructionInfo.eOperandClassification ) )
			{
				pInstruction->setSourceRegisters.insert( objOperand );
			}
		}

		// We additionally tag registers that were explicitly defined, rather than implicitly defined
		pInstruction->setExplicitRegisters.insert( objOperand );
	}
}

///
/// Find the operands for the instruction for ARM and THUMB
///
void
FindARMOperands( INSTRUCTION *pInstruction, const INSTRUCTION_INFO& objInstructionInfo, PCWSTR *ppwzRegisters )
{
	// Set the implicit operands
	const OPERAND *pOperands = (const OPERAND *) objInstructionInfo.arrImplicitSourceRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setSourceRegisters.insert( *pOperands );
		pOperands++;
	}

	pOperands = (const OPERAND *) objInstructionInfo.arrImplicitDestinationRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setDestinationRegisters.insert( *pOperands );
		pOperands++;
	}

	pOperands = (const OPERAND *) objInstructionInfo.arrImplicitDestinationPointerRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setDestinationPointerRegisters.insert( *pOperands );
		pOperands++;
	}

	pOperands = (const OPERAND *) objInstructionInfo.arrImplicitPassedOrReturnedRegisters;

	while( (pOperands != NULL) && pOperands->pwzOperand != NULL )
	{
		pInstruction->setPassedOrReturnedRegisters.insert( *pOperands );
		pOperands++;
	}

	if( objInstructionInfo.eOperandClassification == NO_OPERANDS )
	{
		return;
	}

	// Set our search rules. Note that we have some special case code to handle the way frame pointer references
	// are done in Windows on ARM, and we have additional special case code to handle the multiple register groupings
	bool fInSource = !HAS_DEST_OPERANDS( objInstructionInfo.eOperandClassification ) || HAS_OPERAND_ORDER_REVERSED( objInstructionInfo.eOperandClassification );
	bool fInIndirectReference = false;
	bool fInMonitoredPointerReference = false;
	bool fInMultipleReference = false;
	DWORD cInitialOperands = HAS_DUAL_INITIAL_OPERANDS( objInstructionInfo.eOperandClassification ) ? 2 : 1;
	DWORD cOperandsFound = 0;
	PCWSTR pwzMonitoredPointerOperand = NULL;
	PCWSTR pwzMonitoredRangeOperand = NULL;
	size_t cchMonitoredRangeOperand = 0;

	PCWSTR pwzOperand = pInstruction->pwzArguments;
	PCWSTR pwzNextOperand = NULL;
	size_t cchOperand;
	WCHAR chDelimiter;

	while( FindNextOperand( pwzOperand, L"{}[], -+#!", &pwzNextOperand, &cchOperand, &chDelimiter ) )
	{
		// Prepare for the next iteration
		PCWSTR pwzCurrentOperand = pwzOperand;
		pwzOperand = pwzNextOperand;

		// Cache state information for this iteration
		bool fWasInIndirectReference = fInIndirectReference;
		bool fWasInSource = fInSource;
		bool fWasInMonitoredRangeOperand = (pwzMonitoredRangeOperand != NULL);

		// Check the delimiter we found, because it can change things
		switch( chDelimiter )
		{
			case ',':
				{
					if( !fInMultipleReference )
					{
						cOperandsFound += 1;

						if( cInitialOperands >= cOperandsFound )
						{
							if( HAS_OPERAND_ORDER_REVERSED( objInstructionInfo.eOperandClassification ) )
							{
								fInSource = !HAS_DEST_OPERANDS( objInstructionInfo.eOperandClassification );
							}
							else
							{
								fInSource = HAS_SOURCE_OPERANDS( objInstructionInfo.eOperandClassification );
							}
						}
					}
				}
				break;

			case '{':
				fInMultipleReference = true;
				break;

			case '}':
				{
					fInMultipleReference = false;
				}
				break;

			case '[':
				fInIndirectReference = true;
				break;

			case ']':
				fInIndirectReference = false;

				if( fInMonitoredPointerReference )
				{					
					OPERAND objOperand;
					
					objOperand.pwzOperand = pwzMonitoredPointerOperand;
					objOperand.cchOperand = (pwzCurrentOperand - pwzMonitoredPointerOperand) + cchOperand;
				
					if( fWasInSource )
					{
						pInstruction->setSourceRegisters.insert( objOperand );
					}
					else
					{
						// If the destination operand is flagged as being unaffected by the instruction, don't add it
						// to the destination register set
						if( !HAS_DEST_OPERAND_AS_UNAFFECTED( objInstructionInfo.eOperandClassification ) )
						{
							pInstruction->setDestinationRegisters.insert( objOperand );
						}

						// If the destination is flagged as being an implied source register, we add it to the 
						// implied source registers as well
						if( HAS_DEST_OPERAND_AS_IMPLIED_SOURCE( objInstructionInfo.eOperandClassification ) )
						{
							pInstruction->setSourceRegisters.insert( objOperand );
						}
					}

					// We additionally tag registers that were explicitly defined, rather than implicitly defined
					pInstruction->setExplicitRegisters.insert( objOperand );

					// And we tag compound registers because we want to be able to invalidate them 
					// if the indexing registers are changed
					if( ::wcscspn( objOperand.pwzOperand, L", #+-" ) < objOperand.cchOperand )
					{
						pInstruction->setCompoundRegisters.insert( objOperand );
					}

					fInMonitoredPointerReference = false;
					pwzMonitoredPointerOperand = NULL;

					// And we're done, since we've added the pointer reference as a logical register
					continue;
				}
				break;

			case '-':
				{
					if( fInMultipleReference )
					{
						// We have a range of registers to add here( e.g. r4-r7), so we need to parse them out
						pwzMonitoredRangeOperand = pwzCurrentOperand;
						cchMonitoredRangeOperand = cchOperand;
					}
					else
					{
						continue;
					}
				}
				break;
		}

		// Continue if we don't have any actual operand
		if( cchOperand == 0 )
		{
			continue;
		}

		// Otherwise, we have to check the operand found to see if we are going to add it to the list
		if( IsStringInSet( pwzCurrentOperand, cchOperand, ARM_EXCLUDED_OPERANDS ) )
		{
			fInMonitoredPointerReference = false;
			pwzMonitoredPointerOperand = NULL;
			continue;
		}

		/// Skip the numbers
		if( iswdigit( *pwzCurrentOperand ) )
		{
			continue;
		}

		// Skip items in parentheses 
		if( *pwzCurrentOperand == '(' )
		{
			fInMonitoredPointerReference = false;
			pwzMonitoredPointerOperand = NULL;
			continue;
		}

		// Skip anything that isn't a register
		if( !IsStringInSet( pwzCurrentOperand, cchOperand, ppwzRegisters ) )
		{
			continue;
		}

		// Check to see if this is relative to either r11 (Frame Pointer) or sp (Stack Pointer)
		// for using it as a monitored reference
		//
		// Temporary test: Do this for all cases
		if( fInIndirectReference &&
			(pwzMonitoredPointerOperand == NULL) )
		{
			fInMonitoredPointerReference = true;
			pwzMonitoredPointerOperand = pwzCurrentOperand;
		}

		// Add the register(s)
		if( fWasInSource )
		{
			if( fWasInMonitoredRangeOperand )
			{
				AddRegisterRangeToSet( pwzMonitoredRangeOperand, cchMonitoredRangeOperand, pwzCurrentOperand, cchOperand, &pInstruction->setSourceRegisters );	
			}
			else
			{
				AddOperandToSet( pwzCurrentOperand, cchOperand, &pInstruction->setSourceRegisters );
			}
		}
		else
		{
			// If the destination operand is flagged as being unaffected by the instruction, don't add it
			// to the destination register set
			if( !HAS_DEST_OPERAND_AS_UNAFFECTED( objInstructionInfo.eOperandClassification ) )
			{
				if( fWasInIndirectReference || !HAS_DEST_REGISTERS( objInstructionInfo.eOperandClassification) )
				{
					if( fWasInMonitoredRangeOperand )
					{
						AddRegisterRangeToSet( pwzMonitoredRangeOperand, cchMonitoredRangeOperand, pwzCurrentOperand, cchOperand, &pInstruction->setDestinationPointerRegisters );	
					}
					else
					{
						AddOperandToSet( pwzCurrentOperand, cchOperand, &pInstruction->setDestinationPointerRegisters );
					}
				}
				else
				{
					if( fWasInMonitoredRangeOperand )
					{
						AddRegisterRangeToSet( pwzMonitoredRangeOperand, cchMonitoredRangeOperand, pwzCurrentOperand, cchOperand, &pInstruction->setDestinationRegisters );	
					}
					else
					{
						AddOperandToSet( pwzCurrentOperand, cchOperand, &pInstruction->setDestinationRegisters );
					}
				}
			}

			// If the destination is flagged as being an implied source register, we add it to the 
			// implied source registers as well
			if( HAS_DEST_OPERAND_AS_IMPLIED_SOURCE( objInstructionInfo.eOperandClassification ) )
			{
				if( fWasInMonitoredRangeOperand )
				{
					AddRegisterRangeToSet( pwzMonitoredRangeOperand, cchMonitoredRangeOperand, pwzCurrentOperand, cchOperand, &pInstruction->setSourceRegisters );	
				}
				else
				{
					AddOperandToSet( pwzCurrentOperand, cchOperand, &pInstruction->setSourceRegisters );
				}
			}
		}

		// We additionally tag registers that were explicitly defined, rather than implicitly defined
		if( fWasInMonitoredRangeOperand )
		{
			AddRegisterRangeToSet( pwzMonitoredRangeOperand, cchMonitoredRangeOperand, pwzCurrentOperand, cchOperand, &pInstruction->setExplicitRegisters );	
		}
		else
		{
			AddOperandToSet( pwzCurrentOperand, cchOperand, &pInstruction->setExplicitRegisters );
		}

		// And we clear the range operand if it was set prior to this, since they can only occur adjacent to each other
		if( fWasInMonitoredRangeOperand )
		{
			pwzMonitoredRangeOperand = NULL;
			cchMonitoredRangeOperand = 0;
		}
	}
}


///
/// Extract conditional execution information and flags affecting functionality from ARM / THUMB instructions
///
/// Format:
///    mnemonic{S}{ConditionalExecutionCode}{.W|N}
/// 
/// All the trailing variants are valid
///
/// IMPORTANT: For this to work, the mnemonics in the table need to be stored as the complete root (up to where the
//             flag or conditional execution fields would be) and as a non-exact match
///
void
ParseARMMnemonic( INSTRUCTION *pInstruction, const OPERAND_SET& setProcessorFlags )
{
	DWORD	iComparator;
	size_t	cchMnemonic;

	// Boundary checks for missing mnemonics
	if( pInstruction->pwzMnemonic == NULL )
	{
		return;
	}

	cchMnemonic = ::wcslen( pInstruction->pwzMnemonic );

	if( cchMnemonic <= 1 )
	{
		return;
	}

	// Now set the comparator as we walk forward looking for conditional execution and the set flag
	iComparator = pInstruction->pInstructionInfo->cchMnemonic;

	if( cchMnemonic == iComparator )
	{
		return;
	}

	// Look for the set flag
	if( cchMnemonic != iComparator )
	{
		if( pInstruction->pwzMnemonic[iComparator] == 's' )
		{
			AddOperandToSet( FLAGS_REGISTER, &pInstruction->setDestinationRegisters );
			iComparator += 1;
		}
	}

	// And look for conditional execution flags, which will either result in a no-op, normal execution,
	// or an unpredictable branch instruction
	if( (cchMnemonic - iComparator) >= 2 )
	{
		bool fConditionalExecution = false;
		bool fConditionalExecutionMatch = false;
		bool fExplicitUnconditionalExecution = false;

		switch( pInstruction->pwzMnemonic[iComparator] )
		{
			case 'a':
				{
						switch( pInstruction->pwzMnemonic[iComparator+1] )
						{
							case 'l':
								{
									fExplicitUnconditionalExecution = true;
								}
								break;

							default:
								break;
						}
				}
				break;

			case 'c':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'c':
							{
								AddOperandToSet( CARRY_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = !DoesSetContainOperand( CARRY_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						case 's':
							{
								AddOperandToSet( CARRY_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = DoesSetContainOperand( CARRY_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'e':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'q':
							{
								AddOperandToSet( ZERO_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = DoesSetContainOperand( ZERO_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'g':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'e':
							{
								AddOperandToSet( SIGN_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( OVERFLOW_FLAG, &pInstruction->setSourceRegisters );
								bool fSignFlag = DoesSetContainOperand( SIGN_FLAG, setProcessorFlags);
								bool fOverflowFlag = DoesSetContainOperand( OVERFLOW_FLAG, setProcessorFlags);
								fConditionalExecutionMatch = (fSignFlag == fOverflowFlag);
								fConditionalExecution = true;
							}
							break;

						case 't':
							{
								AddOperandToSet( ZERO_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( SIGN_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( OVERFLOW_FLAG, &pInstruction->setSourceRegisters );

								bool fZeroFlag = DoesSetContainOperand( ZERO_FLAG, setProcessorFlags);
								bool fSignFlag = DoesSetContainOperand( SIGN_FLAG, setProcessorFlags);
								bool fOverflowFlag = DoesSetContainOperand( OVERFLOW_FLAG, setProcessorFlags);
								fConditionalExecutionMatch = !fZeroFlag && (fSignFlag == fOverflowFlag);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'h':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'i':
							{
								AddOperandToSet( ZERO_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( CARRY_FLAG, &pInstruction->setSourceRegisters );
								bool fZeroFlag = DoesSetContainOperand( ZERO_FLAG, setProcessorFlags);
								bool fCarryFlag = DoesSetContainOperand( CARRY_FLAG, setProcessorFlags);
								fConditionalExecutionMatch = fCarryFlag && !fZeroFlag;
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'l':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'e':
							{
								AddOperandToSet( ZERO_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( SIGN_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( OVERFLOW_FLAG, &pInstruction->setSourceRegisters );
								bool fZeroFlag = DoesSetContainOperand( ZERO_FLAG, setProcessorFlags);
								bool fSignFlag = DoesSetContainOperand( SIGN_FLAG, setProcessorFlags);
								bool fOverflowFlag = DoesSetContainOperand( OVERFLOW_FLAG, setProcessorFlags);
								fConditionalExecutionMatch = fZeroFlag || (fSignFlag != fOverflowFlag);
								fConditionalExecution = true;
							}
							break;

						case 's':
							{
								AddOperandToSet( ZERO_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( CARRY_FLAG, &pInstruction->setSourceRegisters );
								bool fZeroFlag = DoesSetContainOperand( ZERO_FLAG, setProcessorFlags);
								bool fCarryFlag = DoesSetContainOperand( CARRY_FLAG, setProcessorFlags);
								fConditionalExecutionMatch = !fCarryFlag || fZeroFlag;
								fConditionalExecution = true;
							}
							break;

						case 't':
							{
								AddOperandToSet( SIGN_FLAG, &pInstruction->setSourceRegisters );
								AddOperandToSet( OVERFLOW_FLAG, &pInstruction->setSourceRegisters );
								bool fSignFlag = DoesSetContainOperand( SIGN_FLAG, setProcessorFlags);
								bool fOverflowFlag = DoesSetContainOperand( OVERFLOW_FLAG, setProcessorFlags);
								fConditionalExecutionMatch = (fSignFlag != fOverflowFlag);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'm':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'i':
							{
								AddOperandToSet( SIGN_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = DoesSetContainOperand( SIGN_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'n':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'e':
							{
								AddOperandToSet( ZERO_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = !DoesSetContainOperand( ZERO_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'p':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'l':
							{
								AddOperandToSet( SIGN_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = !DoesSetContainOperand( SIGN_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			case 'v':
				{
					switch( pInstruction->pwzMnemonic[iComparator+1] )
					{
						case 'c':
							{
								AddOperandToSet( OVERFLOW_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = !DoesSetContainOperand( OVERFLOW_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						case 's':
							{
								AddOperandToSet( OVERFLOW_FLAG, &pInstruction->setSourceRegisters );
								fConditionalExecutionMatch = DoesSetContainOperand( OVERFLOW_FLAG, setProcessorFlags);
								fConditionalExecution = true;
							}
							break;

						default:
							break;
					}
				}
				break;

			default:
				break;
		}

		if( fConditionalExecution )
		{
			iComparator += 2;

			if( pInstruction->fFlagsRegisterValid )
			{
				if( !fConditionalExecutionMatch )
				{
					pInstruction->eClass = NOOP;
				}
			}
			else
			{
				// Whether or not this instruction will be executed cannot be determined
				pInstruction->eClass = UNPREDICTABLE_CONDITIONAL_EXECUTION;
			}
		}
		else if( fExplicitUnconditionalExecution )
		{
			iComparator += 2;
		}
	}
}

///
/// Classify an X86 instruction as part of disassembly
///
bool
ClassifyX86Instruction( INSTRUCTION *pInstruction )
{
	DWORD cMnemonics = sizeof( X86_DISASSEMBLY_INFO ) / sizeof( INSTRUCTION_INFO );
	
	for( DWORD iMnemonic = 0; iMnemonic < cMnemonics; iMnemonic++ )
	{
		if( wcsncmp( X86_DISASSEMBLY_INFO[iMnemonic].pwzMnemonic, pInstruction->pwzMnemonic, X86_DISASSEMBLY_INFO[iMnemonic].cchMnemonic ) == 0 )
		{
			if( !X86_DISASSEMBLY_INFO[iMnemonic].fExactMatch ||
				(wcscmp( X86_DISASSEMBLY_INFO[iMnemonic].pwzMnemonic, pInstruction->pwzMnemonic ) == 0) )
			{
				pInstruction->eClass = X86_DISASSEMBLY_INFO[iMnemonic].eClassification;
				pInstruction->pInstructionInfo = &X86_DISASSEMBLY_INFO[iMnemonic];

				Findx86_x64Operands( pInstruction, X86_DISASSEMBLY_INFO[iMnemonic], X86_REGISTERS );

				// Allow for special case post-processing; this was originally added to handle the common practice
				// of using reflexive XOR operations in x86 or x64 assembly to clear registers
				for( int iAnalysisFunc = 0; iAnalysisFunc < MAX_ANALYSIS_FUNCTIONS; iAnalysisFunc++ )
				{
					if( X86_DISASSEMBLY_INFO[iMnemonic].arrAnalysisOverrideFunctions[iAnalysisFunc] == NULL )
					{
						break;
					}
					else
					{
						X86_DISASSEMBLY_INFO[iMnemonic].arrAnalysisOverrideFunctions[iAnalysisFunc]( pInstruction );
					}
				}

				pInstruction->fFlagsRegisterModified = DoesInstructionModifyFlags( *pInstruction );

				return( true );
			}
		}
	}

	return( true );
}

///
/// Classify an X64 instruction as part of disassembly
///
bool
ClassifyX64Instruction( INSTRUCTION * pInstruction )
{
	DWORD cMnemonics = sizeof( X64_DISASSEMBLY_INFO ) / sizeof( INSTRUCTION_INFO );
	
	for( DWORD iMnemonic = 0; iMnemonic < cMnemonics; iMnemonic++ )
	{
		if( wcsncmp( X64_DISASSEMBLY_INFO[iMnemonic].pwzMnemonic, pInstruction->pwzMnemonic, X64_DISASSEMBLY_INFO[iMnemonic].cchMnemonic ) == 0 )
		{
			if( !X64_DISASSEMBLY_INFO[iMnemonic].fExactMatch ||
				(wcscmp( X64_DISASSEMBLY_INFO[iMnemonic].pwzMnemonic, pInstruction->pwzMnemonic ) == 0) )
			{
				pInstruction->eClass = X64_DISASSEMBLY_INFO[iMnemonic].eClassification;
				pInstruction->pInstructionInfo = &X64_DISASSEMBLY_INFO[iMnemonic];

				Findx86_x64Operands( pInstruction, X64_DISASSEMBLY_INFO[iMnemonic], X64_REGISTERS );

				// Allow for special case post-processing; this was originally added to handle the common practice
				// of using reflexive XOR operations in x86 or x64 assembly to clear registers
				for( int iAnalysisFunc = 0; iAnalysisFunc < MAX_ANALYSIS_FUNCTIONS; iAnalysisFunc++ )
				{
					if( X64_DISASSEMBLY_INFO[iMnemonic].arrAnalysisOverrideFunctions[iAnalysisFunc] == NULL )
					{
						break;
					}
					else
					{
						X64_DISASSEMBLY_INFO[iMnemonic].arrAnalysisOverrideFunctions[iAnalysisFunc]( pInstruction );
					}
				}

				pInstruction->fFlagsRegisterModified = DoesInstructionModifyFlags( *pInstruction );

				return( true );
			}
		}
	}

	// Go with the default for the moment
	return( true );
}

///
/// Classify an ARM or THUMB (UAL only) instruction as part of disassembly
///
bool
ClassifyARMInstruction( INSTRUCTION * pInstruction, const OPERAND_SET& setProcessorFlags )
{
	DWORD cMnemonics = sizeof( ARM_DISASSEMBLY_INFO ) / sizeof( INSTRUCTION_INFO );
	
	for( DWORD iMnemonic = 0; iMnemonic < cMnemonics; iMnemonic++ )
	{
		if( wcsncmp( ARM_DISASSEMBLY_INFO[iMnemonic].pwzMnemonic, pInstruction->pwzMnemonic, ARM_DISASSEMBLY_INFO[iMnemonic].cchMnemonic ) == 0 )
		{
			if( !ARM_DISASSEMBLY_INFO[iMnemonic].fExactMatch ||
				(wcscmp( ARM_DISASSEMBLY_INFO[iMnemonic].pwzMnemonic, pInstruction->pwzMnemonic ) == 0) )
			{
				pInstruction->eClass = ARM_DISASSEMBLY_INFO[iMnemonic].eClassification;
				pInstruction->pInstructionInfo = &ARM_DISASSEMBLY_INFO[iMnemonic];

				ParseARMMnemonic( pInstruction, setProcessorFlags );
				FindARMOperands( pInstruction, ARM_DISASSEMBLY_INFO[iMnemonic], ARM_REGISTERS );
				
				// Allow for special case post-processing; this was originally added to handle the common practice
				// of using reflexive XOR operations in x86 or x64 assembly to clear registers
				for( int iAnalysisFunc = 0; iAnalysisFunc < MAX_ANALYSIS_FUNCTIONS; iAnalysisFunc++ )
				{
					if( ARM_DISASSEMBLY_INFO[iMnemonic].arrAnalysisOverrideFunctions[iAnalysisFunc] == NULL )
					{
						break;
					}
					else
					{
						ARM_DISASSEMBLY_INFO[iMnemonic].arrAnalysisOverrideFunctions[iAnalysisFunc]( pInstruction );
					}
				}

				pInstruction->fFlagsRegisterModified = DoesInstructionModifyFlags( *pInstruction );

				return( true );
			}
		}
	}

	return( true );
}

///
/// Add all the registers starting after the first operand until and including the second operand (ARM processors only) to the
/// specified set
void
AddRegisterRangeToSet( PCWSTR pwzFirstOperand, size_t cchFirstOperand, PCWSTR pwzSecondOperand, size_t cchSecondOperand, OPERAND_SET * psetOperands )
{
	if( (pwzFirstOperand == NULL) || (cchFirstOperand <= 1) || 
		(pwzSecondOperand == NULL) || (cchSecondOperand <= 1) || (psetOperands == NULL) )
	{
		return;
	}

	// We'll just cycle through the registers, this is only supported for ARM, so we'll encode that in
	PCWSTR *ppwzRegisters = ARM_REGISTERS;
	bool fRangeStarted = false;

	while( *ppwzRegisters != NULL )
	{
		if( !fRangeStarted )
		{
			fRangeStarted = ( wcsncmp( *ppwzRegisters, pwzFirstOperand, cchFirstOperand ) == 0 );
		}
		else
		{
			AddOperandToSet( *ppwzRegisters, psetOperands );

			if( wcsncmp( *ppwzRegisters, pwzSecondOperand, cchSecondOperand ) == 0 )
			{
				return;
			}
		}

		ppwzRegisters += 1;
	}
}

///
// Add an operand to an operand set by name
void
AddOperandToSet( PCWSTR pwzOperandName, size_t cchOperandName, OPERAND_SET *psetOperands )
{
	if( (pwzOperandName == NULL) || (cchOperandName == 0) || (psetOperands == NULL) )
	{
		return;
	}

	OPERAND objOperand;
	objOperand.pwzOperand = pwzOperandName;
	objOperand.cchOperand = cchOperandName;

	psetOperands->insert( objOperand );
}

///
// Add an operand to an operand set by name
void
AddOperandToSet( PCWSTR pwzOperandName, OPERAND_SET *psetOperands )
{
	if( (pwzOperandName == NULL) || (psetOperands == NULL) )
	{
		return;
	}

	OPERAND objOperand;
	objOperand.pwzOperand = pwzOperandName;
	objOperand.cchOperand = wcslen( pwzOperandName );
	psetOperands->insert( objOperand );
}

///
// Does the set contain an operand of the given name
bool
DoesSetContainOperand( PCWSTR pwzOperandName, const OPERAND_SET &setOperands )
{
	if( pwzOperandName == NULL )
	{
		return( false );
	}

	OPERAND objOperand;
	objOperand.pwzOperand = pwzOperandName;
	objOperand.cchOperand = wcslen( pwzOperandName );

	return( setOperands.find( objOperand ) != setOperands.end() );
}

///
// Sort a set of operands against an arbitrary order
const OPERAND *
GetSortedOperandsList( const OPERAND_SET &setOperands, PCWSTR arrOrder[] )
{
	size_t cOperands = setOperands.size();
	OPERAND *pOperands = new OPERAND[cOperands+1];
	size_t iOperand = 0;
	PCWSTR *ppwzRegister = arrOrder;

	while( ppwzRegister && *ppwzRegister && iOperand < cOperands )
	{
		if( DoesSetContainOperand( *ppwzRegister, setOperands ) )
		{
			pOperands[iOperand].cchOperand = wcslen( *ppwzRegister );
			pOperands[iOperand].pwzOperand = *ppwzRegister;
			iOperand += 1;
		}

		ppwzRegister += 1;
	}

	pOperands[iOperand].cchOperand = 0;
	pOperands[iOperand].pwzOperand = NULL;

	return( pOperands );
}

///
/// Return an array of operands (terminated with a NULL operand) that is the specified
/// operand set in Push order for the processor, or NULL if the processor does not support
/// arbitrary multiple register stack operations
const OPERAND *
GetOperandsInPushOrder( DWORD dwProcessor, const OPERAND_SET &setOperands )
{
	switch( dwProcessor )
	{
		case IMAGE_FILE_MACHINE_ARM:
		case IMAGE_FILE_MACHINE_THUMB:
		case IMAGE_FILE_MACHINE_ARMNT:
			{
				return( GetSortedOperandsList( setOperands, ARM_REGISTERS_PUSH_ORDER ) );
			}
			break;

		default:
				return( NULL );
	}
}

///
/// Return an array of operands (terminated with a NULL operand) that is the specified
/// operand set in Pop order for the processor, or NULL if the processor does not support
/// arbitrary multiple register stack operations
const OPERAND * 
GetOperandsInPopOrder( DWORD dwProcessor, const OPERAND_SET &setOperands )
{
	switch( dwProcessor )
	{
		case IMAGE_FILE_MACHINE_ARM:
		case IMAGE_FILE_MACHINE_THUMB:
		case IMAGE_FILE_MACHINE_ARMNT:
			{
				return( GetSortedOperandsList( setOperands, ARM_REGISTERS_POP_ORDER ) );
			}
			break;

		default:
				return( NULL );
	}
}

///
// Analysis Override Functions
///

///
// Overide Function
// Remove the explicit source register references if they are also the explicit destination reference. This analysis override is primarily
// used for reflexive XOR operations
//
// This should only be used in cases (like the x86/x64 XOR EAX,EAX common pattern) where the result is independent of the
// source registers values
void
ReflexiveCancellationAnalysisOverride( INSTRUCTION *pInstruction  )
{
	bool fIsReflexive = true;

	for( OPERAND_SET::const_iterator itOperand = pInstruction->setDestinationRegisters.begin(); fIsReflexive && (itOperand != pInstruction->setDestinationRegisters.end()); itOperand++ )
	{
		if( pInstruction->setExplicitRegisters.find( *itOperand ) != pInstruction->setExplicitRegisters.end() )
		{
			if( pInstruction->setSourceRegisters.find( *itOperand ) == pInstruction->setSourceRegisters.end() )
			{
				fIsReflexive = false;
			}
		}
	}

	for( OPERAND_SET::const_iterator itOperand = pInstruction->setSourceRegisters.begin(); fIsReflexive && (itOperand != pInstruction->setSourceRegisters.end()); itOperand++ )
	{
		if( pInstruction->setExplicitRegisters.find( *itOperand ) != pInstruction->setExplicitRegisters.end() )
		{
			if( pInstruction->setDestinationRegisters.find( *itOperand ) == pInstruction->setDestinationRegisters.end() )
			{
				fIsReflexive = false;
			}
		}
	}

	// If all of the source registers are also destination registers, then we clear the source registers because
	// effectively we only have a destination register
	if( fIsReflexive )
	{
		pInstruction->setSourceRegisters.clear();
	}
}

///
// Override Function
//
// Look for any branch where the link register is the source, and convert that into a return op-code
void
ARMImplicitReturnAnalysisOverride( INSTRUCTION *pInstruction )
{
	if( (pInstruction->eClass == BRANCH) && DoesSetContainOperand( L"lr", pInstruction->setSourceRegisters ) )
	{
		pInstruction->eClass = RETURN;

		// Add the calling convention return arguments
		AddOperandToSet( L"r0", &pInstruction->setPassedOrReturnedRegisters );
		AddOperandToSet( L"r1", &pInstruction->setPassedOrReturnedRegisters );
	}
}

///
// Override Function
//
// Look for any data move operation where the program counter is the destination, and convert that into a branch op-code
void
ARMImplicitBranchAnalysisOverride( INSTRUCTION *pInstruction )
{
	switch( pInstruction->eClass )
	{
		case DATA_MOVE:
			{
				if( DoesSetContainOperand( L"pc", pInstruction->setDestinationRegisters ) )
				{
					pInstruction->eClass = BRANCH;
				}
			}
			break;

		case STACK_POP:
			{
				if( DoesSetContainOperand( L"pc", pInstruction->setDestinationRegisters ) )
				{
					// Note: We are overtainting here, because by setting this to a branch instruction, we lose the ability
					//       for the taint engine to track the lightweight stack taint.
					// 
					// @TODO: Look for a way to keep the lightweight tracking along with the branch in a future build
					pInstruction->eClass = BRANCH;

					AddOperandToSet( STACK_CONTENTS, &pInstruction->setSourceRegisters );
				}
			}
			break;

		default:
			break;
	}
}

///
// Override Function
//
// Look for any data move operation which has the update-pointer decoration (!), and turn it into a block data move
void
ARMBlockMoveAnalysisOverride( INSTRUCTION *pInstruction )
{
	switch( pInstruction->eClass )
	{
		case DATA_MOVE:
			{
				if( ::wcsrchr( pInstruction->pwzArguments, L'!' ) != NULL )
				{
					pInstruction->eClass = BLOCK_DATA_MOVE;
				}
			}
			break;

		default:
			break;

	}
}

