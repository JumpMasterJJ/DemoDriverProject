// LstProcDlg.cpp : implementation file
//

#include "stdafx.h"
#include "ListProc.h"
#include "LstProcDlg.h"
#include "Instdrv.h"
#include <winioctl.h>
#include "ioctlcmd.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/////////////////////////////////////////////////////////////////////////////
// CLstProcDlg dialog


extern CHAR ac_driverLabel[];
extern CHAR ac_driverName[];
int CLstProcDlg::m_columnClicked= -1;
int CLstProcDlg::m_nClicked = 0;


#define DRIVER_NAME _T("KillProc")
#define DRIVER_PATH _T(".\\KillProc.sys")

HANDLE gh_Device = INVALID_HANDLE_VALUE;

CWinThread	*g_hReadThread = NULL;
BOOL	g_bToExitThread = FALSE;
HANDLE	g_hOverlappedEvent = NULL;

BOOL LoadDriver(TCHAR* lpszDriverName,TCHAR* lpszDriverPath)
{
	TCHAR szDriverImagePath[256] = {0};
	//得到完整的驱动路径
	GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr=NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK=NULL;//NT驱动程序的服务句柄

	//打开服务控制管理器
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );

	if( hServiceMgr == NULL )  
	{
		//OpenSCManager失败
		//printf( "OpenSCManager() Failed %d ! \n", GetLastError() );
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager成功
		printf( "OpenSCManager() ok ! \n" );  
	}

	//创建驱动所对应的服务
	hServiceDDK = CreateService( hServiceMgr,
		lpszDriverName, //驱动程序的在注册表中的名字  
		lpszDriverName, // 注册表驱动程序的 DisplayName 值  
		SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限  
		SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序  
		SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值  
		SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值  
		szDriverImagePath, // 注册表驱动程序的 ImagePath 值  
		NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
		NULL,  
		NULL,  
		NULL,  
		NULL);  

	DWORD dwRtn;
	//判断服务是否失败
	if( hServiceDDK == NULL )  
	{  
		dwRtn = GetLastError();
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS )  
		{  
			//由于其他原因创建服务失败
			//printf( "CrateService() Failed %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{
			//服务创建失败，是由于服务已经创立过
			printf( "CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n" );  
		}

		// 驱动程序已经加载，只需要打开  
		hServiceDDK = OpenService( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );  
		if( hServiceDDK == NULL )  
		{
			//如果打开服务也失败，则意味错误
			dwRtn = GetLastError();  
			//printf( "OpenService() Failed %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else 
		{
			//printf( "OpenService() ok ! \n" );
		}
	}  
	else  
	{
		//printf( "CrateService() ok ! \n" );
	}

	//开启此项服务
	bRet= StartService( hServiceDDK, NULL, NULL );  
	if( !bRet )  
	{  
		DWORD dwRtn = GetLastError();  
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING )  
		{  
			//printf( "StartService() Failed %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{  
			if( dwRtn == ERROR_IO_PENDING )  
			{  
				//设备被挂住
				//printf( "StartService() Failed ERROR_IO_PENDING ! \n");
				bRet = FALSE;
				goto BeforeLeave;
			}  
			else  
			{  
				//服务已经开启
				//printf( "StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \n");
				bRet = TRUE;
				goto BeforeLeave;
			}  
		}  
	}
	bRet = TRUE;
//离开前关闭句柄
BeforeLeave:
	if(hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if(hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

//卸载驱动程序  
BOOL UnloadDriver( TCHAR * szSvrName )  
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr=NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK=NULL;//NT驱动程序的服务句柄
	SERVICE_STATUS SvrSta;
	//打开SCM管理器
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );  
	if( hServiceMgr == NULL )  
	{
		//带开SCM管理器失败
		printf( "OpenSCManager() Failed %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{
		//带开SCM管理器失败成功
		printf( "OpenSCManager() ok ! \n" );  
	}
	//打开驱动所对应的服务
	hServiceDDK = OpenService( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );  

	if( hServiceDDK == NULL )  
	{
		//打开驱动所对应的服务失败
		printf( "OpenService() Failed %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{  
		printf( "OpenService() ok ! \n" );  
	}  
	//停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
	if( !ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) )  
	{  
		printf( "ControlService() Failed %d !\n", GetLastError() );  
	}  
	else  
	{
		//打开驱动所对应的失败
		printf( "ControlService() ok !\n" );  
	}  
	//动态卸载驱动程序。  
	if( !DeleteService( hServiceDDK ) )  
	{
		//卸载失败
		printf( "DeleteSrevice() Failed %d !\n", GetLastError() );  
	}  
	else  
	{  
		//卸载成功
		printf( "DelServer:eleteSrevice() ok !\n" );  
	}  
	bRet = TRUE;
BeforeLeave:
//离开前关闭打开的句柄
	if(hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if(hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;	
} 

HANDLE OpenDevice()
{
	//测试驱动程序  
	HANDLE hDevice = CreateFile(_T("\\\\.\\KillProc"),  
		GENERIC_WRITE | GENERIC_READ,  
		0,  
		NULL,  
		OPEN_EXISTING,  
		0,  
		NULL);  
	if( hDevice != INVALID_HANDLE_VALUE )  
	{
		printf( "Create Device ok ! \n" );  
	}
	else  
	{
		printf( "Create Device faild %d ! \n", GetLastError() ); 
		return NULL;
	}

	return hDevice;
} 

CLstProcDlg::CLstProcDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CLstProcDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CLstProcDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void CLstProcDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CLstProcDlg)
	DDX_Control(pDX, IDC_LIST, m_procListCtrl);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CLstProcDlg, CDialog)
	//{{AFX_MSG_MAP(CLstProcDlg)
	ON_BN_CLICKED(IDC_PROC, OnProc)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST, OnColumnclickList)
	ON_COMMAND(ID_KILLPROCESS, OnKillprocess)
	ON_COMMAND(ID_BAIDU, OnBaidu)
	ON_COMMAND(ID_GOOGLE, OnGoogle)
	ON_NOTIFY(NM_RCLICK, IDC_LIST, OnRclickList)
	ON_COMMAND(ID_FORCE_KILLPROC, OnForceKillproc)
	ON_COMMAND(ID_PROTECT_PROC, OnProtectProc)
	ON_WM_CLOSE()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CLstProcDlg message handlers
//Windows NT Functions

typedef BOOL (WINAPI *ENUMPROCESSES)(
  DWORD * lpidProcess,  // array to receive the process identifiers
  DWORD cb,             // size of the array
  DWORD * cbNeeded      // receives the number of bytes returned
);

typedef DWORD (WINAPI *GETMODULEFILENAMEA)( 
  HANDLE hProcess,		// handle to the process
  HMODULE hModule,		// handle to the module
  LPSTR lpstrFileName,	// array to receive filename
  DWORD nSize			// size of filename array.
);

typedef DWORD (WINAPI *GETMODULEFILENAMEW)( 
  HANDLE hProcess,		// handle to the process
  HMODULE hModule,		// handle to the module
  LPWSTR lpstrFileName,	// array to receive filename
  DWORD nSize			// size of filename array.
);

#define	GETMODULEFILENAME	GETMODULEFILENAMEA


typedef BOOL (WINAPI *ENUMPROCESSMODULES)(
  HANDLE hProcess,      // handle to the process
  HMODULE * lphModule,  // array to receive the module handles
  DWORD cb,             // size of the array
  LPDWORD lpcbNeeded    // receives the number of bytes returned
);

int CALLBACK CLstProcDlg::ListViewCompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{

	CListCtrl* list=(CListCtrl*)lParamSort;
	CString s1,s2;	
	int result,i1,i2,n1,n2;
	LVFINDINFO findInfo;	
	findInfo.flags=LVFI_PARAM;	
	findInfo.lParam=lParam1;	
	n1=list->FindItem(&findInfo,-1);	
	findInfo.lParam=lParam2;	
	n2=list->FindItem(&findInfo,-1);	
	s1=list->GetItemText(n1,m_columnClicked);	
	s2=list->GetItemText(n2,m_columnClicked);	
	switch(m_columnClicked) 
		{	
		case 0:		
			i1=atoi(s1);		
			i2=atoi(s2);		
			if(m_nClicked%2==1)				
				result=i1>i2?1:(i1<i2?-1:0);		
			else 			
				result=i1>i2?-1:(i1<i2?1:0);		
			break;	
		default:			
			if(m_nClicked%2==1)
			{
				int len = strlen(s1);
				for(int i=0;i<len;i++)
					s1.SetAt(i,toupper(s1[i]));
				len = strlen(s2);
				for(int i=0;i<len;i++)
					s2.SetAt(i, toupper(s2[i]));
				result=strcmp(s1,s2);
			}
			else 
			{
				int len = strlen(s1);
				for(int i=0;i<len;i++)
					s1.SetAt(i,toupper(s1[i]));
				len = strlen(s2);
				for(int i=0;i<len;i++)
					s2.SetAt(i,toupper(s2[i]));
				result=strcmp(s2,s1);
			}
			break;
		}		
		return result;
}
void CLstProcDlg::OnProc() 
{
	ENUMPROCESSES       pEnumProcesses = NULL;
	GETMODULEFILENAME   pGetModuleFileName = NULL;
	ENUMPROCESSMODULES  pEnumProcessModules = NULL; 

	HMODULE modPSAPI = LoadLibrary(_T("PSAPI.DLL"));
	pEnumProcesses = (ENUMPROCESSES)GetProcAddress(modPSAPI, "EnumProcesses");
	pGetModuleFileName = (GETMODULEFILENAME)GetProcAddress(modPSAPI, "GetModuleFileNameExA");
	pEnumProcessModules = (ENUMPROCESSMODULES)GetProcAddress(modPSAPI, "EnumProcessModules");
	if(pEnumProcesses == NULL ||
		pGetModuleFileName == NULL ||
		pEnumProcessModules == NULL)
		return;

	DWORD nProcessIDs[1024];
	DWORD nProcessNo;

	BOOL bSuccess = pEnumProcesses(nProcessIDs, sizeof(nProcessIDs), &nProcessNo);
	if ( !bSuccess )
	{
			return;
	}  

	nProcessNo /= sizeof(nProcessIDs[0]);
	m_procListCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES); 
	m_procListCtrl.DeleteAllItems();  
	while(m_procListCtrl.DeleteColumn(0));
	m_procListCtrl.InsertColumn(1,"PID",LVCFMT_CENTER,50);  
 
	m_procListCtrl.InsertColumn(2,"映像位置与名称",LVCFMT_LEFT,700);  

	for ( unsigned i=0; i<nProcessNo; i++)
	{
			int m;
			HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, 
								FALSE, nProcessIDs[i]);
			DWORD error=GetLastError();

			HMODULE hModules[1024];
			DWORD nModuleNo;
			TCHAR szFileName[MAX_PATH];

			pEnumProcessModules(process, hModules, sizeof(hModules), &nModuleNo);

			nModuleNo /= sizeof(hModules[0]);

			if ( pGetModuleFileName(process, hModules[0], szFileName, sizeof(szFileName)) )
			{
					CString strPid;
					CString strName;
					strPid.Format("%u",nProcessIDs[i]);
					strName.Format("%s",szFileName);
					m = m_procListCtrl.InsertItem(i, strPid);
					m_procListCtrl.SetItemText(m,1,strName); 
			}
			CloseHandle(process);
	}
	return;
	
}


void CLstProcDlg::OnColumnclickList(NMHDR* pNMHDR, LRESULT* pResult) 
{
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
	m_nClicked++;
	int col = pNMListView->iSubItem;	
	m_columnClicked=col;	
	int nItemCounter=m_procListCtrl.GetItemCount();
	for(int i=0;i<nItemCounter;i++)
		m_procListCtrl.SetItemData(i,i);
	int result=m_procListCtrl.SortItems((PFNLVCOMPARE)CLstProcDlg::ListViewCompareFunc,(LPARAM)&m_procListCtrl); 	
	*pResult = 0;
}

void CLstProcDlg::OnKillprocess() 
{

	DWORD dw;
	if(m_dwPID==-1)
	{
		MessageBox("请选择进程");
		return;
	}
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 
								FALSE, m_dwPID);
	if(process!=NULL)
	{
	GetExitCodeProcess(process,&dw); 
	TerminateProcess(process,dw);
	MessageBox(_T("进程已被终止"),_T("终止进程"),MB_OK);
	}
	else
		MessageBox(_T("进程终止失败"),_T("终止进程"),MB_OK);	
}

void CLstProcDlg::OnBaidu() 
{
	// TODO: Add your command handler code here
	ShellExecute(NULL, "open", "http://www.baidu.com/s?wd="+m_strSearch,  
             NULL, NULL, SW_SHOWNORMAL); 
}

void CLstProcDlg::OnGoogle() 
{
	ShellExecute(NULL, "open", "http://www.google.cn/search?q="+m_strSearch,  
             NULL, NULL, SW_SHOWNORMAL); 	
}

void CLstProcDlg::OnRclickList(NMHDR* pNMHDR, LRESULT* pResult) 
{

    LONG pid;
    CMenu menu , *pSubMenu;//定义下面要用到的cmenu对象
	
    menu.LoadMenu(IDR_RIGHT);//装载自定义的右键菜单
    pSubMenu = menu.GetSubMenu(0);//获取第一个弹出菜单，所以第一个菜单必须有子菜单
    CPoint oPoint;//定义一个用于确定光标位置的位置
    GetCursorPos( &oPoint);//获取当前光标的位置，以便使得菜单可以跟随光标

    int istat=m_procListCtrl.GetSelectionMark();//用istat存放当前选定的是第几项
    m_strSearch =m_procListCtrl.GetItemText(istat,1);//获取当前项中的数据，0代表是第0列
	m_dwPID = (pid=atol(m_procListCtrl.GetItemText(istat,0)))>0?pid:-1;
    pSubMenu->TrackPopupMenu (TPM_LEFTALIGN, oPoint.x, oPoint.y, this); //在指定位置显示弹出菜单

	*pResult = 0;	
}

void CLstProcDlg::OnForceKillproc() 
{
	DWORD ret = 0;
	DWORD read;
	if(m_dwPID==-1)
	{
		MessageBox("请选择进程");
		return;
	}
	if(MessageBox(_T("强杀进程可能会造成系统不稳定，确认要进行吗？"),_T("强杀进程"),MB_YESNO)==IDYES)
	{
		DeviceIoControl(gh_Device, 
						IOCTL_PROC_KILL,
						&m_dwPID,
						sizeof(m_dwPID),
						&ret,
						sizeof(ret),
						&read,
						NULL);

		//UnloadDeviceDriver(ac_driverName);
		if(ret==0)
			MessageBox(_T("成功执行"));
		else
			MessageBox(_T("执行失败"));
		//ShellExecute(NULL, "open", "sc","stop LstProc", NULL, SW_HIDE); 

		
	}	
}

BOOL CLstProcDlg::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here

	OnProc();
	SetTimer(1000, 5*1000, NULL);

	BOOL bRet = LoadDriver(DRIVER_NAME,DRIVER_PATH);
	if (!bRet)
	{
		MessageBox(_T("加载驱动失败"), _T("Error"), MB_OK);
		return FALSE;
	}
	
	
	gh_Device = OpenDevice();
	if (gh_Device == NULL)
	{
		MessageBox(_T("打开设备失败"), _T("Error"), MB_OK);
		return FALSE;
	}
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CLstProcDlg::OnProtectProc() 
{
	DWORD ret	= -1;
	DWORD read	= 0;

	if(m_dwPID==-1)
	{
		MessageBox("请选择进程");
		return;
	}
	if(MessageBox(_T("确认要进行保护吗？"),_T("保护进程"),MB_YESNO)==IDYES)
	{
		DeviceIoControl(gh_Device, 
			IOCTL_PROC_PROTECT,
			&m_dwPID,
			sizeof(m_dwPID),
			&ret,
			sizeof(ret),
			&read,
			NULL);
		//UnloadDeviceDriver(ac_driverName);
		if(ret==0)
			MessageBox(_T("保护成功执行"));
		else
			MessageBox(_T("保护执行失败"));
		//ShellExecute(NULL, "open", "sc","stop LstProc", NULL, SW_HIDE); 
		
		
	}	
}

void CLstProcDlg::OnClose() 
{
	// TODO: Add your message handler code here and/or call default

	if (gh_Device != INVALID_HANDLE_VALUE)
	{
		CloseHandle(gh_Device);
	}
	ShellExecute(NULL, "open", "sc","stop KillProc", NULL, SW_HIDE);
	CDialog::OnClose();
}

void CLstProcDlg::OnTimer(UINT nIDEvent) 
{
	// TODO: Add your message handler code here and/or call default
	OnProc();
	CDialog::OnTimer(nIDEvent);
}
