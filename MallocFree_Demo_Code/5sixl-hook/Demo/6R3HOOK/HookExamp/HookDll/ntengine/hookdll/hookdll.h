// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the HOOKDLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// HOOKDLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef HOOKDLL_EXPORTS
#define HOOKDLL_API __declspec(dllexport)
#else
#define HOOKDLL_API __declspec(dllimport)
#endif

// This class is exported from the hookdll.dll
class HOOKDLL_API Chookdll {
public:
	Chookdll(void);
	// TODO: add your methods here.
};

extern HOOKDLL_API int nhookdll;

HOOKDLL_API int fnhookdll(void);

extern "C"  // 把函数原型放里面
{
	BOOL WINAPI DllMain(HINSTANCE hInstance,DWORD What,LPVOID NotUsed);
}


