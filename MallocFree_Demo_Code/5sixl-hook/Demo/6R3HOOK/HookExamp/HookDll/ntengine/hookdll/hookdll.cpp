// hookdll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "hookdll.h"


// This is an example of an exported variable
HOOKDLL_API int nhookdll=0;

// This is an example of an exported function.
HOOKDLL_API int fnhookdll(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see hookdll.h for the class definition
Chookdll::Chookdll()
{
	return;
}
