/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2012 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/* ===================================================================== */
/*
  @ORIGINAL_AUTHOR: Robert Muth
*/

/* ===================================================================== */
/*! @file
 *  This file contains an ISA-portable PIN tool for tracing instructions
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <string.h>

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "calltrace.out", "specify trace file name");
KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "print call arguments ");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces a call trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

string invalid = "invalid_rtn";
ADDRINT gtargetAddress;

/* ===================================================================== */
VOID get_target(ADDRINT target, BOOL taken)
{
    TraceFile << "get_target for: " << target << endl;
    gtargetAddress = target;
}
/* ===================================================================== */
/**
* Given a fully qualified path to a file, this function extracts the raw
* filename and gets rid of the path.
**/
std::string extractFilename(const std::string& filename)
{
    int lastBackslash = filename.rfind("\\");

    if (lastBackslash == -1)
    {
        return filename;
    }
    else
    {
        return filename.substr(lastBackslash + 1);
    }
}
/* ===================================================================== */

/**
* Given an address, this function determines the name of the loaded module the
* address belongs to. If the address does not belong to any module, the empty
* string is returned.
**/
std::string getModule(ADDRINT address)
{
    // To find the module name of an address, iterate over all sections of all
    // modules until a section is found that contains the address.

    for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
    {
        for(SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            if (address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec))
            {
                return extractFilename(IMG_Name(img));
            }
        }
    }

    return "";
}

/* ===================================================================== */
const string *getLib(ADDRINT address)
{
    string filename = getModule(address);
    int lastDot = filename.rfind(".");
    
    if (lastDot == -1)
    {
        return new string(filename);
    }
    else
    {
        return new string(filename.substr(0, lastDot));
    }
    
}
/* ===================================================================== */

const string *Target2String(ADDRINT target)
{
    string name = RTN_FindNameByAddress(target);
    if (name == "")
        return &invalid;
    else
        return new string(name);
}

/* ===================================================================== */

VOID  do_call_args(ADDRINT offset, const string *l, const string *s, ADDRINT arg0)
{
    TraceFile << *l << " + " << offset << " : " << *s << "(" << arg0 << ",...)" << endl;
}

/* ===================================================================== */

VOID  do_call_args_indirect(ADDRINT offset, ADDRINT target, BOOL taken, ADDRINT arg0)
{
    if( !taken ) return;

    const string *l = getLib(target);
    const string *s = Target2String(target);
    do_call_args(offset, l, s, arg0);

    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID  do_call(ADDRINT offset, const string *l, const string *s)
{
    TraceFile  << *l << " + " << offset << " : " << *s << endl;
}

/* ===================================================================== */

VOID  do_call_indirect(ADDRINT offset, ADDRINT target, BOOL taken)
{
    if( !taken ) return;

    const string *l = getLib(target);
    const string *s = Target2String(target);
    do_call(offset, l, s );
    
    if (s != &invalid)
        delete s;
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
    const BOOL print_args = KnobPrintArgs.Value();
    const string *__attribute__((unused)) libName = new string("");
    
        
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS tail = BBL_InsTail(bbl);
        ADDRINT currentaddr = 0;
        ADDRINT startaddress = 0;
        ADDRINT offset = 0;

        if( INS_IsCall(tail) )
        {
            currentaddr = INS_Address(tail);
            IMG currentimage = IMG_FindByAddress(currentaddr);
            if ( IMG_Valid(currentimage) )
            {
                startaddress = IMG_LowAddress(currentimage);
                //printf("%x\t%s\n", startaddress, IMG_Name(currentimage).c_str() );
                offset = currentaddr - startaddress;
            }
            
            if( INS_IsDirectBranchOrCall(tail) )
            {
                const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
                libName = getLib(target);

                if( print_args )
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args),
                                             IARG_ADDRINT, offset, IARG_PTR, getLib(target), IARG_PTR, Target2String(target), IARG_G_ARG0_CALLER, IARG_END);
                }
                else
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call),
                                             IARG_ADDRINT, offset, IARG_PTR, getLib(target), IARG_PTR, Target2String(target), IARG_END);
                }
                

                
            }
            else
            {
                if( print_args)
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_ADDRINT, offset, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_ADDRINT, offset, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
                }
                
            }
        }
        else
        {
            // sometimes code is not in an image
            RTN rtn = TRACE_Rtn(trace);
            
            // also track stup jumps into share libraries
            if( RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && ".plt" == SEC_Name( RTN_Sec( rtn ) ))
            {
                if( print_args )
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,  IARG_G_ARG0_CALLER, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);

                }
            }
        }
        
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    TraceFile << "# eof" << endl;
    
    TraceFile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int  main(int argc, char *argv[])
{
    
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    

    TraceFile.open(KnobOutputFile.Value().c_str());

    TraceFile << hex;
    TraceFile.setf(ios::showbase);
    
    string trace_header = string("#\n"
                                 "# Call Trace Generated By Pin\n"
                                 "#\n");
    

    TraceFile.write(trace_header.c_str(),trace_header.size());
    
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
