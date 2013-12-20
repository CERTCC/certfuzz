//
// taint.cpp
//
// The MSEC Debugger Extension Taint Tracking
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


#define TAINT_MODULE
#include "stdafx.h"
#include "taint.h"
#include "metadisassembler.h"

///
// Update paired operand sets, adding the specified register to the add set, and removing it from the clear set.
//
// This uses the clear aliasing to remove the aliases of the register explicitly from the clear set
void
UpdateInverseOperandSets( DWORD dwProcessor, const OPERAND &objRegister, OPERAND_SET *psetAdd, OPERAND_SET *psetClear )
{
	psetAdd->insert( objRegister );

	const OPERAND *pRegisterAliases = GetRegisterAliases( dwProcessor, objRegister.pwzOperand, objRegister.cchOperand, CLEAR_TAINT );

	if( pRegisterAliases == NULL )
	{
		psetClear->erase( objRegister );
	}
	else
	{
		while( pRegisterAliases->pwzOperand != NULL )
		{
			psetClear->erase( *pRegisterAliases );
			pRegisterAliases++;
		}
	}
}

///
// AssignTaint
//
// Trace the taint through an instruction block
//
// Taint Tracking Rules:
//
// An instruction is considered tainted (i.e. has a set of tainted input registers) if any of the following conditions is true:
//
// 1. Source registers for the instruction are tainted
// 2. Destination pointer registers for the instruction are tainted
// 3. Passed or returned registers for the instruction are tainted
//
// Taint propagates as follows:
//
// The initial instruciton is presumed to have all source instructions tainted.
//
// If any of the source registers for an instruction are tainted, the taint will propagate to the destination registers, except in the case of
// DATA_EXCHANGE metainstructions, in which case the taint for the source and the destination registers is exchanged. In no case does taint flow to or
// from the Destination Pointer registers or the Passed or Returned registers.
//
// In the case of PUSH and POP operations, the taint is pushed onto or popped off of a lightweight stack emulator. For push/pop instructions, we currently support
// only two modes. If there is an explicit source/destination register, taint tracks with that. If there are one or more implicit source/destination registers, the taint
// tracks with those in the order in which they were defined in the instruction definition. We do not currently support the ability to combine both explicit and implicit 
// register tracking in the same instruction.
//
// If at any point there are no possible taint sources, taint tracking can end.
bool
AssignTaint( DWORD dwProcessor, bool fTaintInitialDestinationPointerRegisters, __in INSTRUCTION_LIST *pInstructionBlock )
{
	StackEmulator objVirtualStack;
	OPERAND_SET setTaint;
	OPERAND_SET setClear;
	bool fAnalyzingFaultingInstruction = true;
	bool fMultipleExplicitStackOperandsValid = (dwProcessor == IMAGE_FILE_MACHINE_ARM) || (dwProcessor == IMAGE_FILE_MACHINE_THUMB) || (dwProcessor == IMAGE_FILE_MACHINE_ARMNT);
	bool fExplicitMemoryReferenceStackOperandsValid = (dwProcessor == IMAGE_FILE_MACHINE_I386) || (dwProcessor == IMAGE_FILE_MACHINE_AMD64);

	INSTRUCTION_LIST::const_iterator itInstruction = pInstructionBlock->begin();

	while(  itInstruction != pInstructionBlock->end()  )
	{
		OPERAND_SET setExpandedTaint;
		INSTRUCTION *pInstruction = *itInstruction;
		itInstruction++;

		if( fAnalyzingFaultingInstruction )
		{
			setTaint = pInstruction->setSourceRegisters;

			if( fTaintInitialDestinationPointerRegisters )
			{
				for( OPERAND_SET::const_iterator itOperand = pInstruction->setDestinationPointerRegisters.begin(); itOperand != pInstruction->setDestinationPointerRegisters.end(); itOperand++ )
				{
					pInstruction->setTaintedInputRegisters.insert( *itOperand );
				}
			}

			fAnalyzingFaultingInstruction = false;
		}

		// If the taint pool is empty, we have no more work to do
		if( setTaint.empty() && !objVirtualStack.HasTaintedElements() )
		{
			return( true );
		}

		// If this instruction is a no-op, there is no point in doing the rest of the calculations
		if( pInstruction->eClass == NOOP )
		{
			continue;
		}

		// Calculate the "expanded" taint set that we need to both determine the incoming taint for this instruction
		// and the taint set for the next instruction
		for( OPERAND_SET::const_iterator itOperand = setTaint.begin(); itOperand != setTaint.end(); itOperand++ )
		{
			const OPERAND *pRegisterAliases = GetRegisterAliases( dwProcessor, itOperand->pwzOperand, itOperand->cchOperand, SET_TAINT );

			if( pRegisterAliases == NULL )
			{
				if( setClear.find( *itOperand  ) == setClear.end() )
				{
					setExpandedTaint.insert( *itOperand );
				}
			}
			else
			{
				while( pRegisterAliases->pwzOperand != NULL )
				{
					if( setClear.find( *pRegisterAliases ) == setClear.end() )
					{
						setExpandedTaint.insert( *pRegisterAliases );
					}

					pRegisterAliases++;
				}
			}
		}

		// Handle the special case operand which determines if the contents of the stack (somewhere in the contents) 
		// are known to be tainted
		if( objVirtualStack.HasTaintedElements() )
		{
			static OPERAND opStackOperand = OPERAND_ENTRY( STACK_CONTENTS );
			setExpandedTaint.insert( opStackOperand );
		}

		// Set the source operand taint for this instruction
		for( OPERAND_SET::const_iterator itOperand = pInstruction->setSourceRegisters.begin(); itOperand != pInstruction->setSourceRegisters.end(); itOperand++ )
		{
			if( setExpandedTaint.find( *itOperand ) != setExpandedTaint.end() )
			{
				pInstruction->setTaintedInputRegisters.insert( *itOperand );
			}
		}
		
		for( OPERAND_SET::const_iterator itOperand = pInstruction->setDestinationPointerRegisters.begin(); itOperand != pInstruction->setDestinationPointerRegisters.end(); itOperand++ )
		{
			if( setExpandedTaint.find( *itOperand ) != setExpandedTaint.end() )
			{
				pInstruction->setTaintedInputRegisters.insert( *itOperand );
			}
		}

		for( OPERAND_SET::const_iterator itOperand = pInstruction->setPassedOrReturnedRegisters.begin(); itOperand != pInstruction->setPassedOrReturnedRegisters.end(); itOperand++ )
		{
			if( setExpandedTaint.find( *itOperand ) != setExpandedTaint.end() )
			{
				pInstruction->setTaintedInputRegisters.insert( *itOperand );
			}
		}

		// And calculate the taint sets for the next instruction
		if( itInstruction != pInstructionBlock->end() )
		{
			switch( pInstruction->eClass )
			{
				case STACK_POP:
					{
						if( pInstruction->setExplicitRegisters.size() == 0 )
						{
							const OPERAND *pOperand = (const OPERAND *) pInstruction->pInstructionInfo->arrImplicitDestinationRegisters;

							while( pOperand->pwzOperand )
							{
								bool fWasTainted = objVirtualStack.Pop();

								if( fWasTainted )
								{
									UpdateInverseOperandSets( dwProcessor, *pOperand, &setTaint, &setClear );
								}
								else
								{
									UpdateInverseOperandSets( dwProcessor, *pOperand, &setClear, &setTaint );
								}

								pOperand++;
							}
						}
						else
						{
							if( pInstruction->setDestinationRegisters.size() == 1 )
							{
								bool fWasTainted = objVirtualStack.Pop();

								if( fWasTainted )
								{
									UpdateInverseOperandSets( dwProcessor, *(pInstruction->setDestinationRegisters.begin()), &setTaint, &setClear );
								}
								else
								{
									UpdateInverseOperandSets( dwProcessor, *(pInstruction->setDestinationRegisters.begin()), &setClear, &setTaint );
								}
							}
							else if( pInstruction->setDestinationPointerRegisters.size() != 0 )
							{
								if( fExplicitMemoryReferenceStackOperandsValid )
								{
									// We are moving the data to memory. In order to allow us to analyze this, we're going to specifically
									// add the StackContents as a source register, and add it to the taint set. This is sub-optimum, and
									// should be revisited, because we are overloading the use of the StackContents, but we'll do it here
									// because it seems to be the cleanest answer at the moment
									bool fWasTainted = objVirtualStack.Pop();

									if( fWasTainted )
									{						
										OPERAND objStackContents = OPERAND_ENTRY( STACK_CONTENTS );

										pInstruction->setSourceRegisters.insert( objStackContents );
										pInstruction->setTaintedInputRegisters.insert( objStackContents );
									}
								}
								else
								{
									return( false );
								}
							}
							else
							{
								if( fMultipleExplicitStackOperandsValid )
								{
									const OPERAND *pOperands = GetOperandsInPopOrder( dwProcessor, pInstruction->setDestinationRegisters );
									const OPERAND *pOperand = pOperands;

									while( pOperand && pOperand->pwzOperand )
									{
										bool fWasTainted = objVirtualStack.Pop();

										if( fWasTainted )
										{
											UpdateInverseOperandSets( dwProcessor, *pOperand, &setTaint, &setClear );
										}
										else
										{
											UpdateInverseOperandSets( dwProcessor, *pOperand, &setClear, &setTaint );
										}

										pOperand += 1;
									}

									delete[] pOperands;
								}
								else
								{
									return( false );
								}
							}
						}
					}
					break;

				case STACK_PUSH:
					{
						if( pInstruction->setExplicitRegisters.size() == 0 )
						{
							const OPERAND *pOperand = (const OPERAND *) pInstruction->pInstructionInfo->arrImplicitSourceRegisters;

							while( pOperand->pwzOperand )
							{
								objVirtualStack.Push( *pOperand, setExpandedTaint );
								pOperand++;
							}
						}
						else
						{
							if( pInstruction->setSourceRegisters.size() == 1 )
							{
								objVirtualStack.Push( *(pInstruction->setSourceRegisters.begin()), setExpandedTaint );
							}
							else if( pInstruction->setSourceRegisters.size() == 0 )
							{
								// We have no implicit source registers, and no explicit source registers, which means we are pushing a single constant, at least
								// for all instruction sets currently supported. If this changes, we'll need to revisit this assumption
								objVirtualStack.PushConstant();
							}
							else
							{
								if( fExplicitMemoryReferenceStackOperandsValid )
								{
									// We are going to assume that this is a push from a calculated memory address. This is a
									// potentially a very CPU dependent assumption, but we've called out the risks of our stack model
									// now. If we have any tainted source registers in our calculation, we'll use them
									objVirtualStack.Push( pInstruction->setSourceRegisters, setExpandedTaint );
								}
								else if( fMultipleExplicitStackOperandsValid )
								{
									const OPERAND *pOperands = GetOperandsInPushOrder( dwProcessor, pInstruction->setSourceRegisters );
									const OPERAND *pOperand = pOperands;

									while( pOperand && pOperand->pwzOperand )
									{
										objVirtualStack.Push( *pOperand, setExpandedTaint );
										pOperand += 1;
									}

									delete[] pOperands;
								}
								else
								{
									return( false );
								}
							}
						}
					}
					break;

				case DATA_EXCHANGE:
					{
						bool fSourceTainted = false;
						bool fDestinationTainted = false;

						// Determine if this instruction uses tainted sources
						for( OPERAND_SET::const_iterator itOperand = pInstruction->setSourceRegisters.begin(); !fSourceTainted && itOperand != pInstruction->setSourceRegisters.end(); itOperand++ )
						{
							if( setExpandedTaint.find( *itOperand ) != setExpandedTaint.end() )
							{
								fSourceTainted = true;
								break;
							}
						}

						// Determine if this instruction uses tainted sources
						for( OPERAND_SET::const_iterator itOperand = pInstruction->setDestinationRegisters.begin(); !fDestinationTainted && itOperand != pInstruction->setDestinationRegisters.end(); itOperand++ )
						{
							if( setExpandedTaint.find( *itOperand ) != setExpandedTaint.end() )
							{
								fDestinationTainted = true;
								break;
							}
						}

						// And update the master taint sets:
						// We have two tracking sets of taint, those being those operands known explicitly to be tainted, and those
						// known explicitly to be untainted. From these we already computed our expanded set of tainted registers for this
						// pass, now we update them. Anything we add to one is then cleared (via an expanded clear) from the other.
						for( OPERAND_SET::const_iterator itOperand = pInstruction->setSourceRegisters.begin(); itOperand != pInstruction->setSourceRegisters.end(); itOperand++ )
						{
							if( fDestinationTainted )
							{
								UpdateInverseOperandSets( dwProcessor, *itOperand, &setTaint, &setClear );
							}
							else
							{
								UpdateInverseOperandSets( dwProcessor, *itOperand, &setClear, &setTaint );
							}
						}

						for( OPERAND_SET::const_iterator itOperand = pInstruction->setDestinationRegisters.begin(); itOperand != pInstruction->setDestinationRegisters.end(); itOperand++ )
						{
							if( fSourceTainted )
							{
								UpdateInverseOperandSets( dwProcessor, *itOperand, &setTaint, &setClear );
							}
							else
							{
								UpdateInverseOperandSets( dwProcessor, *itOperand, &setClear, &setTaint );
							}
						}

					}
					break;

				default:
					{
						bool fSourceTainted = false;

						// Determine if this instruction uses tainted sources
						for( OPERAND_SET::const_iterator itOperand = pInstruction->setSourceRegisters.begin(); !fSourceTainted && itOperand != pInstruction->setSourceRegisters.end(); itOperand++ )
						{
							if( setExpandedTaint.find( *itOperand ) != setExpandedTaint.end() )
							{
								fSourceTainted = true;
								break;
							}
						}

						// And update the master taint sets:
						// We have two tracking sets of taint, those being those operands known explicitly to be tainted, and those
						// known explicitly to be untainted. From these we already computed our expanded set of tainted registers for this
						// pass, now we update them. Anything we add to one is then cleared (via an expanded clear) from the other.
						for( OPERAND_SET::const_iterator itOperand = pInstruction->setDestinationRegisters.begin(); itOperand != pInstruction->setDestinationRegisters.end(); itOperand++ )
						{
							if( fSourceTainted )
							{
								UpdateInverseOperandSets( dwProcessor, *itOperand, &setTaint, &setClear );
							}
							else
							{
								UpdateInverseOperandSets( dwProcessor, *itOperand, &setClear, &setTaint );
							}
						}
					}
					break;
			}
		}
	}

	return( true );
}

