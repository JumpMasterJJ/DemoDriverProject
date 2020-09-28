/***************************************************************
Module name: LibSpyDll.h
Copyright (c) 2003 Robert Kuster

Notice:	If this code works, it was written by Robert Kuster.
		Else, I don't know who wrote it.

		Use it on your own risk. No responsibilities for
		possible damages of even functionality can be taken.
***************************************************************/
#if !defined LIBSPY_DLL_H
#define LIBSPY_DLL_H

#ifdef LIBSPY_DLL_EXPORTS
#define LIBSPY_API __declspec(dllexport)
#else
#define LIBSPY_API __declspec(dllimport)
#endif

extern LIBSPY_API HWND	g_hPwdEdit;
extern LIBSPY_API char	g_szPassword [128];

#endif // !defined(LIBSPY_DLL_H)