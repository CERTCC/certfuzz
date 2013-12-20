#ifndef __DiplayHook_H
#define __DiplayHook_H
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the DISPLAYHOOK_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// DISPLAYHOOK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DISPLAYHOOK_EXPORTS
#define DISPLAYHOOK_API  extern "C" __declspec(dllexport)
#else
#define DISPLAYHOOK_API  extern "C" __declspec(dllimport)
#endif
#include <windows.h>
#define DISPLAY_HOOK_MSG _T("CERT-DISPLAY_HOOK_MSG-{DCF7FBEE-DAF2-4325-86D0-52E532ADAE63}")

typedef BOOL (* HookDisplayType)(HWND);
typedef BOOL (* UnhookDisplayType)(HWND);
DISPLAYHOOK_API BOOL HookDisplay(HWND hWnd);
DISPLAYHOOK_API BOOL UnhookDisplay(HWND hWnd);
#endif
