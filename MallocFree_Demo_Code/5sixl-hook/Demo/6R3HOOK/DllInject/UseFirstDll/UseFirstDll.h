// UseFirstDll.h : main header file for the USEFIRSTDLL application
//

#if !defined(AFX_USEFIRSTDLL_H__9F9F9695_C01F_4773_A55F_E2D7EA3452D8__INCLUDED_)
#define AFX_USEFIRSTDLL_H__9F9F9695_C01F_4773_A55F_E2D7EA3452D8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CUseFirstDllApp:
// See UseFirstDll.cpp for the implementation of this class
//

class CUseFirstDllApp : public CWinApp
{
public:
	CUseFirstDllApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CUseFirstDllApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CUseFirstDllApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_USEFIRSTDLL_H__9F9F9695_C01F_4773_A55F_E2D7EA3452D8__INCLUDED_)
