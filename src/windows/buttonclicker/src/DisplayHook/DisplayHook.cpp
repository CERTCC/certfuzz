// DisplayHook.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "DisplayHook.h"
#include <tchar.h>

static HINSTANCE DllInstance =  NULL;
static HHOOK     HookHandle = NULL;
static UINT      MSG_DISPLAY_HOOK;

#pragma data_seg(".DisplayHookDll")
static HWND hWndServer = NULL;
#pragma data_seg()
#pragma comment(linker, "/section:.DisplayHookDll,rws")

static  LRESULT CALLBACK HookCallBack(int nCode, WPARAM wParam, LPARAM lParam);

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DllInstance = (HINSTANCE)hModule;
		MSG_DISPLAY_HOOK = RegisterWindowMessage(DISPLAY_HOOK_MSG);
		 break;
	case DLL_THREAD_ATTACH:
		 break;
	case DLL_THREAD_DETACH:
         break;
	case DLL_PROCESS_DETACH:
		 if(hWndServer != NULL)
           UnhookDisplay(hWndServer);
		break;
	}
    return TRUE;
}


DISPLAYHOOK_API BOOL HookDisplay(HWND hWnd)
{
  if(hWndServer != NULL)
      return FALSE;
   HookHandle = SetWindowsHookEx(
                            WH_CBT,
                           (HOOKPROC)HookCallBack,
                           DllInstance,
                           0);
   if(HookHandle != NULL)
     { /* success */
      hWndServer = hWnd;
      return TRUE;
     } /* success */
   return FALSE;

}
DISPLAYHOOK_API BOOL UnhookDisplay(HWND hWnd)
{
    if(hWnd != hWndServer)
       return FALSE;
    BOOL unhooked = UnhookWindowsHookEx(HookHandle);
    if(unhooked)
       hWndServer = NULL;
    return unhooked;
}

static LRESULT CALLBACK HookCallBack(int nCode, WPARAM wParam, LPARAM lParam)
{
 if ((nCode == HCBT_ACTIVATE)||
	 (nCode == HCBT_DESTROYWND)||
	 (nCode == HCBT_CREATEWND))
   {
	//HWND hWnd = (HWND) wParam;
	PostMessage(hWndServer,MSG_DISPLAY_HOOK,  wParam, nCode); 
   }
   return CallNextHookEx(HookHandle, nCode, wParam, lParam);
}
