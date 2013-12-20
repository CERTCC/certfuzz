#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <locale.h>
#include <stdio.h>
#include <malloc.h>
#include "DisplayHook.h"
#define MAX_ENV_VAR_SIZE 32767


#define MAX_BUTTONS 1024

typedef struct _WindowDataBase
 {
  _WindowDataBase    *pNext;
  _WindowDataBase    *pPrev;
  HWND                WindowHandle;
 }TWindowDataBase;

typedef struct
{
 WNDCLASS  ThreadWindowClass;
 HWND      WindowHandle;
} THiddenWindow;

char *ButtonNames[]=
{
	"Restart",
	"Open",
	"OK",
	"Accept",
	"Agree",
	"Decline",
	"Yes",
	"Continue",
    "No",
	"Cancel",
	"Close",
	"Don't Send",
};

typedef enum
{
 RESTART=0,
 OPEN=1,
 OK=2,
 ACCEPT=3,
 AGREE=4,
 DECLINE=5,
 YES=6,
 CONTINUE=7,
 NO=8,
 CANCEL=9,
 CLOSE=10,
 DONTSEND=11,
 NUM_BUTTONS=12
} TButtonTypes;

typedef struct
{
 HWND          WindowHandle;
 TButtonTypes  ButtonType;
} TButtonInfo;

typedef struct
{
 TButtonInfo Button[MAX_BUTTONS];
 DWORD       NumButtons;
} TButtonList;

static void  FreeWindow(THiddenWindow *HiddenWindow);
static THiddenWindow *  AllocateWindow(HWND hWnd,WNDPROC lpfnWndProc);
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static BOOL CALLBACK EnumWindowsProc(HWND hwnd,LPARAM lParam);
static BOOL CALLBACK EnumChildWindowCallback(HWND hwnd, LPARAM lParam);
static BOOL AddWindow(HWND hwnd);
static void RemoveWindow(TWindowDataBase *pNode);
static void DeleteAllWindows(void);
static DWORD WINAPI  WindowMonitorThreadProc(LPVOID arg);
static BOOL CheckButtons(TButtonList *ButtonList);
static BOOL CALLBACK CheckUnhookableCallback(HWND hwnd, LPARAM lParam);
static void CheckUnhookable(void);

static  THiddenWindow      * HookHiddenWindow=NULL;
static  UINT                 MSG_DISPLAY_HOOK;
static  TWindowDataBase    * pWindowHead=NULL;
static  TWindowDataBase    * pWindowTail=NULL;
static  TWindowDataBase    * FindWindow(HWND hwnd);
static  HANDLE               WindowMonitorThread=NULL;
static  HINSTANCE            dllHookHandle = NULL;

static  HookDisplayType     HookDisplayFptr=NULL;
static  UnhookDisplayType   UnhookDisplayFptr=NULL;

static  HANDLE              ThreadReady=NULL;

static  BOOL                SendCloseWindows;


////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// BOOL WindowMonitorStart(void)                                                     //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
BOOL WindowMonitorStart(BOOL CloseWindows)
{
 DWORD id;
 char *OldPath;
 char *NewPath;

 if ((OldPath=(char *)malloc(MAX_ENV_VAR_SIZE))==NULL)
 {
   return(FALSE);
 }
 if ((NewPath=(char *)malloc(MAX_ENV_VAR_SIZE))==NULL)
 {
   free(OldPath);
   return(FALSE);
 }

 if (GetEnvironmentVariable(TEXT("Path"),OldPath,MAX_ENV_VAR_SIZE)==0)
 {
	 free(NewPath);
	 free(OldPath);
	 return(FALSE);
 }

 strcpy(NewPath,OldPath);
 strcat(NewPath,";");
#if _DEBUG
strcat(NewPath,"..//..//DisplayHook//Debug");
#else
strcat(NewPath,"..//..//DisplayHook//Release");
#endif
SendCloseWindows=CloseWindows;
if (SetEnvironmentVariable(TEXT("Path"),NewPath)==0)
{
  free(NewPath);
  free(OldPath); 
  return(FALSE);
}
free(NewPath);
dllHookHandle=LoadLibrary("DisplayHook.dll");
SetEnvironmentVariable(TEXT("Path"),OldPath);
free(OldPath); 
if (dllHookHandle==NULL) return(FALSE);
HookDisplayFptr=(HookDisplayType)GetProcAddress(dllHookHandle,"HookDisplay");
UnhookDisplayFptr=(UnhookDisplayType)GetProcAddress(dllHookHandle,"UnhookDisplay");

if (HookDisplayFptr==NULL) printf("GetProcAddress Hook failed\n");
if (UnhookDisplayFptr==NULL) printf("GetProcAddress UNHook failed\n");

if ((HookDisplayFptr==NULL)||(UnhookDisplayFptr==NULL)) return(FALSE);
printf("Loaded DLL\n");
ThreadReady = CreateEvent( NULL, FALSE, FALSE, NULL );
 WindowMonitorThread = CreateThread(NULL, 0, WindowMonitorThreadProc, (LPVOID)NULL, CREATE_SUSPENDED, &id);
 if (WindowMonitorThread==NULL)
	 {
      CloseHandle(ThreadReady);
	  return(FALSE);
	 }
 ResumeThread(WindowMonitorThread);
 WaitForSingleObject(ThreadReady, INFINITE );// FIX ME should use timeout
 CloseHandle(ThreadReady);
 return(TRUE);
}

////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// void WindowMonitorStop(void)                                                     //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
BOOL WindowMonitorStop(void)
{
 DWORD WaitResult;
 
 if (dllHookHandle==NULL) return(FALSE);

 PostMessage(HookHiddenWindow->WindowHandle, WM_DESTROY, 0xDEAD, 0xBEEF );
 WaitResult=WaitForSingleObject(WindowMonitorThread,INFINITE);
  if (WaitResult==WAIT_OBJECT_0)
  {
   CloseHandle(WindowMonitorThread);
   WindowMonitorThread=NULL;
   FreeLibrary(dllHookHandle);       
   dllHookHandle=NULL;
   return(TRUE);
  }
  else return(FALSE);
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// WindowMonitorThreadProc(LPVOID arg);                                                    //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static DWORD WINAPI WindowMonitorThreadProc(LPVOID arg) 
{
 MSG         msg ; 
 _tsetlocale(LC_CTYPE, _T(""));
 MSG_DISPLAY_HOOK = RegisterWindowMessage(DISPLAY_HOOK_MSG);
 if (EnumWindows(EnumWindowsProc,NULL)==FALSE)
 {
  printf("Could not save all previously opened windows\n");
 }
 HookHiddenWindow=AllocateWindow(NULL,WndProc);
 PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);
 
 if (HookHiddenWindow==NULL)
   {
    printf("Can't allocate window\n");
	return(0);
   }
   if (HookDisplayFptr(HookHiddenWindow->WindowHandle))
   {
    BOOL bRet;
	printf("Display Hooked\n");
	fflush(stdout);
	SetEvent(ThreadReady);
	SetTimer(HookHiddenWindow->WindowHandle,0xBEEF,1000,(TIMERPROC) NULL);    
    while (1)
          { 
		   bRet=GetMessage (&msg, NULL, 0, 0);
		   if ((bRet != -1) && (bRet!=0))
		   {
            TranslateMessage (&msg) ; 
            DispatchMessage (&msg) ;
		   }
		   else if ((bRet==0)&&(msg.wParam==0xDEADBEEF)) break; 
          } 
	KillTimer(HookHiddenWindow->WindowHandle,0xBEEF);
	if (UnhookDisplayFptr(HookHiddenWindow->WindowHandle))
	 {
      printf("Display Unhooked\n");
	  fflush(stdout);
	 }

   FreeWindow(HookHiddenWindow);
   DeleteAllWindows();
  }
  else  SetEvent(ThreadReady); // FIX ME should use timeout
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// THiddenWindow *  AllocateWindow(HWND hWnd,WNDPROC lpfnWndProc)                    //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static THiddenWindow *  AllocateWindow(HWND hWnd,WNDPROC lpfnWndProc)
{
 WNDCLASS  TempClass;
 BOOL      ClassRegistered;
 HINSTANCE hInstance;
 THiddenWindow *HiddenWindow;
 HiddenWindow=(THiddenWindow *)malloc(sizeof(THiddenWindow));
 if (HiddenWindow==NULL) return(NULL);
#pragma warning( push )
#pragma warning( disable : 4312 ) 
 hInstance=(HINSTANCE)GetWindowLong(hWnd,GWL_HINSTANCE);
#pragma warning( pop )
 HiddenWindow->ThreadWindowClass.style=0;
 HiddenWindow->ThreadWindowClass.lpfnWndProc=lpfnWndProc;
 HiddenWindow->ThreadWindowClass.cbClsExtra=0;
 HiddenWindow->ThreadWindowClass.cbWndExtra=0;
 HiddenWindow->ThreadWindowClass.hInstance=hInstance;
 HiddenWindow->ThreadWindowClass.hIcon=0;
 HiddenWindow->ThreadWindowClass.hCursor=0;
 HiddenWindow->ThreadWindowClass.hbrBackground=0;
 HiddenWindow->ThreadWindowClass.lpszMenuName=NULL;
 HiddenWindow->ThreadWindowClass.lpszClassName="DisplayHookWindow";

 ClassRegistered=GetClassInfo(hInstance,HiddenWindow->ThreadWindowClass.lpszClassName,
                              &TempClass);
 if ((!ClassRegistered) || (TempClass.lpfnWndProc!= lpfnWndProc))
 {
  if (ClassRegistered)
     UnregisterClass(HiddenWindow->ThreadWindowClass.lpszClassName, hInstance);
  RegisterClass(&HiddenWindow->ThreadWindowClass);
 }
 HiddenWindow->WindowHandle = CreateWindow(HiddenWindow->ThreadWindowClass.lpszClassName,"", 0, 0, 0, 0, 0, 0, 0,
                        hInstance, NULL);
 if (HiddenWindow->WindowHandle==NULL)
 {
  free(HiddenWindow);
  return(NULL);
 }
 return(HiddenWindow);
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// void FreeWindow(THiddenWindow *HiddenWindow)                                      //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static void  FreeWindow(THiddenWindow *HiddenWindow)
{
	if (HiddenWindow)
	 {
	  DestroyWindow(HiddenWindow->WindowHandle);
	  free(HiddenWindow);
	 }
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// BOOL CALLBACK EnumWindowsProc(HWND hwnd,LPARAM lParam)                            //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static BOOL CALLBACK EnumWindowsProc(HWND hwnd,LPARAM lParam)
{
 return(AddWindow(hwnd));
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// static BOOL AddWindow(HWND hwnd)                                                  //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static BOOL AddWindow(HWND hwnd)
{
 TWindowDataBase *pNode= new TWindowDataBase;
 if (pNode==NULL) return(FALSE);
 pNode->WindowHandle =hwnd;
  if (pWindowHead == NULL)
   {
    pWindowHead = pNode;
    pNode->pPrev = NULL;
   }
 else
   {
    pWindowTail->pNext = pNode;
    pNode->pPrev = pWindowTail;
   }
 pWindowTail = pNode;
 pNode->pNext = NULL;
 return(TRUE);
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// static void RemoveWindow(TWindowDataBase *pNode)                                  //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static void RemoveWindow(TWindowDataBase *pNode)
{
   if (pNode->pPrev == NULL)
      pWindowHead = pNode->pNext;
   else
      pNode->pPrev->pNext = pNode->pNext;
   if (pNode->pNext == NULL)
      pWindowTail = pNode->pPrev;
   else
      pNode->pNext->pPrev = pNode->pPrev;
   delete pNode;
}

////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// static void  DeleteAllWindows(void)                                               //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static void  DeleteAllWindows(void)
{
   while (pWindowHead != NULL)
      RemoveWindow(pWindowHead);
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// static TWindowDataBase * FindWindow(HWND hwnd)                                    //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static TWindowDataBase * FindWindow(HWND hwnd)
{
  TWindowDataBase *pNode;
   for (pNode = pWindowHead; pNode != NULL; pNode = pNode->pNext)
   {
		   if (pNode->WindowHandle==hwnd)
		   {
            return(pNode);		   
		   }
   }
  return(NULL);
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// BOOL CALLBACK EnumChildWindowCallback(HWND hwnd, LPARAM lParam)                   //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static BOOL CALLBACK EnumChildWindowCallback(HWND hwnd, LPARAM lParam)
{
TCHAR ClassName[200],TextBuffer[200];
TButtonList *ButtonList=(TButtonList *)lParam;

GetClassName(hwnd,ClassName,sizeof(ClassName));
GetWindowText(hwnd,TextBuffer,sizeof(TextBuffer));
_tcslwr(ClassName);
_tcslwr(TextBuffer);
if (ButtonList->NumButtons>=MAX_BUTTONS) return(FALSE);
if (_tcsstr(ClassName,"button"))
{
   if(_tcsstr(TextBuffer,_T("accept"))) 
   {
	ButtonList->Button[ButtonList->NumButtons].ButtonType=ACCEPT;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
    ButtonList->NumButtons++;
    return(TRUE);
	}
   else if(_tcsstr(TextBuffer,_T("agree")))
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=AGREE;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
   else if(_tcsstr(TextBuffer,_T("decline")))
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=DECLINE;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
   else if(_tcsstr(TextBuffer,_T("yes")))
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=YES;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
   else if(_tcsstr(TextBuffer,_T("continue")))
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=CONTINUE;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
   else if((_tcsstr(TextBuffer,_T("no")))&&(!_tcsstr(TextBuffer,_T("not"))))
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=NO;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
  else if(_tcsstr(TextBuffer,_T("cancel"))) 
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=CANCEL;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}

   else if(_tcsstr(TextBuffer,_T("close"))) 
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=CLOSE;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
  else if(_tcsstr(TextBuffer,_T("ok"))) 
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=OK;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
  else if(_tcsstr(TextBuffer,_T("don't"))) 
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=DONTSEND;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
   else if(_tcsstr(TextBuffer,_T("open"))) 
   {
 	ButtonList->Button[ButtonList->NumButtons].ButtonType=OPEN;
	ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	ButtonList->NumButtons++;
    return(TRUE);
	}
  else if(_tcsstr(TextBuffer,_T("restart"))) 
   {
	if (SendMessage(hwnd, BM_GETCHECK, 0, 0)==BST_CHECKED)
	{
	 printf("Restart Button Checked\n");
 	 ButtonList->Button[ButtonList->NumButtons].ButtonType=RESTART;
	 ButtonList->Button[ButtonList->NumButtons].WindowHandle=hwnd;
	 ButtonList->NumButtons++;
     return(TRUE);
	}
   }

  }
return(TRUE);
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// void LRESULT CALLBACK WndProc(HWND hWnd, UINT msg,WPARAM wParam, LPARAM lParam)   //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
 if (msg==MSG_DISPLAY_HOOK)
 {
   if (lParam==HCBT_ACTIVATE)
    {
     TButtonList ButtonList;

     ButtonList.NumButtons=0;

     if ((FindWindow((HWND)wParam)==NULL) )//&& 
		  //(FindWindow(GetAncestor((HWND)wParam,GA_ROOTOWNER))==NULL))
	 {
       if (EnumChildWindows((HWND)wParam, EnumChildWindowCallback,(LPARAM)&ButtonList))
        { 
		  if (CheckButtons(&ButtonList)) return(0);
	    }
#ifdef PRINTCAPTIONS
        char Text[512];
		  if (GetWindowText((HWND)wParam,Text,sizeof(Text))>0)
		  {
			  printf("Caption %s\n",Text);
		  }
#endif
       DWORD dwStyle; 
       dwStyle=GetWindowLong((HWND)wParam,GWL_STYLE);
       if (((dwStyle & WS_SYSMENU)==WS_SYSMENU) &&
	       ((dwStyle & WS_CAPTION )==WS_CAPTION))
         {
 
		  if (SendCloseWindows)
		  { 
           printf("Sent WM_CLOSE\n");
           PostMessage((HWND)wParam,WM_CLOSE,0,0);
           printf("Sent WM_QUIT\n");
           PostMessage((HWND)wParam,WM_QUIT,0,0);
		  }

	      return(0);
         }
	 }
	 else 
	 {
	   return DefWindowProc(hWnd, msg, wParam, lParam);
	 }
	}
   else if (lParam==HCBT_CREATEWND)
   {
   }
   else if (lParam==HCBT_DESTROYWND)
   {
    TWindowDataBase  *TmpWindow=FindWindow((HWND)wParam);
    if (TmpWindow)
	{
        RemoveWindow(TmpWindow);
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
   }
   return 0;
 }
 switch (msg)
    { 
         case WM_TIMER :
			   CheckUnhookable();
			   break;
         case WM_DESTROY : 
			   if ((wParam==0xDEAD) && (lParam==0xBEEF)) 
				    PostQuitMessage (0xDEADBEEF) ; 
               break; 
         default: 
			   return DefWindowProc(hWnd, msg, wParam, lParam); 
               break; 
    } 
   return 0;
}

////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// static BOOL CheckButtons(TButtonList *ButtonList)                                 //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static BOOL CheckButtons(TButtonList *ButtonList)
{
 //printf("Button found %d\n",ButtonList.NumButtons);
 for (DWORD i=0;i<NUM_BUTTONS;i++)
 for (DWORD j=0;j<ButtonList->NumButtons;j++)
 	{
     if (ButtonList->Button[j].ButtonType==(TButtonTypes)i)
	   {
	    printf("Sent Handle(0x%08p) %s\n",ButtonList->Button[j].WindowHandle,ButtonNames[ButtonList->Button[j].ButtonType]);
		PostMessage(ButtonList->Button[j].WindowHandle,BM_CLICK,0,0);
		if (ButtonList->Button[j].ButtonType!=RESTART) return(TRUE);
	   }
     }
 return(FALSE);
}

////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// static BOOL CALLBACK CheckUnhookableCallback(HWND hwnd, LPARAM lParam)            //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
static BOOL CALLBACK CheckUnhookableCallback(HWND hwnd, LPARAM lParam)
{
  TButtonList ButtonList;
  ButtonList.NumButtons=0;

  if ((GetWindowLong(hwnd,GWL_STYLE) & WS_VISIBLE))
  {
   if (EnumChildWindows((HWND)hwnd, EnumChildWindowCallback,(LPARAM)&ButtonList))
        { 
         CheckButtons(&ButtonList);
	    }
  }
 return(TRUE);
}
////////////////////////////////////////////////////////////////////////////////////////
///                                                                                   //
/// static void CheckUnhookable(void)                                                 //            
///                                                                                   //
////////////////////////////////////////////////////////////////////////////////////////
void static CheckUnhookable(void)
{
	EnumWindows(CheckUnhookableCallback,0);
}