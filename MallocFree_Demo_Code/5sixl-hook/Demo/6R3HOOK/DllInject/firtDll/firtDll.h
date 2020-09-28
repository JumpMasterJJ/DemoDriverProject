
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the FIRTDLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// FIRTDLL_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef FIRTDLL_EXPORTS
#define FIRTDLL_API __declspec(dllexport)
#else
#define FIRTDLL_API __declspec(dllimport)
#endif

// This class is exported from the firtDll.dll
class FIRTDLL_API CFirtDll {
public:
	CFirtDll(void);
	// TODO: add your methods here.
};


extern FIRTDLL_API int nFirtDll;

extern FIRTDLL_API int a;

FIRTDLL_API int fnFirtDll(void);

