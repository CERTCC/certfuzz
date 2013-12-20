// TestDisplayHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <conio.h>

#include "WindowMonitor.h"


static BOOL CtrlHandler(DWORD fdwCtrlType);

static HANDLE MainThreadHandle;

int _tmain(int argc, _TCHAR* argv[])
{
 DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),GetCurrentProcess(),
                &MainThreadHandle, THREAD_ALL_ACCESS, FALSE, 0);
 SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler, TRUE);
 WindowMonitorStart(false);
 SuspendThread(GetCurrentThread());
 WindowMonitorStop();
 return 0;
}
//---------------------------------------------------------------------------
static BOOL CtrlHandler(DWORD fdwCtrlType)
{
  switch( fdwCtrlType ) 
  { 
    case CTRL_CLOSE_EVENT: 
      return( FALSE );
    default:
     ResumeThread(MainThreadHandle);
     return(TRUE);
  }
}