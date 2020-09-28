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
	//�õ�����������·��
	GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr=NULL;//SCM�������ľ��
	SC_HANDLE hServiceDDK=NULL;//NT��������ķ�����

	//�򿪷�����ƹ�����
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );

	if( hServiceMgr == NULL )  
	{
		//OpenSCManagerʧ��
		//printf( "OpenSCManager() Failed %d ! \n", GetLastError() );
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager�ɹ�
		printf( "OpenSCManager() ok ! \n" );  
	}

	//������������Ӧ�ķ���
	hServiceDDK = CreateService( hServiceMgr,
		lpszDriverName, //�����������ע����е�����  
		lpszDriverName, // ע������������ DisplayName ֵ  
		SERVICE_ALL_ACCESS, // ������������ķ���Ȩ��  
		SERVICE_KERNEL_DRIVER,// ��ʾ���صķ�������������  
		SERVICE_DEMAND_START, // ע������������ Start ֵ  
		SERVICE_ERROR_IGNORE, // ע������������ ErrorControl ֵ  
		szDriverImagePath, // ע������������ ImagePath ֵ  
		NULL,  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
		NULL,  
		NULL,  
		NULL,  
		NULL);  

	DWORD dwRtn;
	//�жϷ����Ƿ�ʧ��
	if( hServiceDDK == NULL )  
	{  
		dwRtn = GetLastError();
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS )  
		{  
			//��������ԭ�򴴽�����ʧ��
			//printf( "CrateService() Failed %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{
			//���񴴽�ʧ�ܣ������ڷ����Ѿ�������
			printf( "CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n" );  
		}

		// ���������Ѿ����أ�ֻ��Ҫ��  
		hServiceDDK = OpenService( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );  
		if( hServiceDDK == NULL )  
		{
			//����򿪷���Ҳʧ�ܣ�����ζ����
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

	//�����������
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
				//�豸����ס
				//printf( "StartService() Failed ERROR_IO_PENDING ! \n");
				bRet = FALSE;
				goto BeforeLeave;
			}  
			else  
			{  
				//�����Ѿ�����
				//printf( "StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \n");
				bRet = TRUE;
				goto BeforeLeave;
			}  
		}  
	}
	bRet = TRUE;
//�뿪ǰ�رվ��
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

//ж����������  
BOOL UnloadDriver( TCHAR * szSvrName )  
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr=NULL;//SCM�������ľ��
	SC_HANDLE hServiceDDK=NULL;//NT��������ķ�����
	SERVICE_STATUS SvrSta;
	//��SCM������
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );  
	if( hServiceMgr == NULL )  
	{
		//����SCM������ʧ��
		printf( "OpenSCManager() Failed %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{
		//����SCM������ʧ�ܳɹ�
		printf( "OpenSCManager() ok ! \n" );  
	}
	//����������Ӧ�ķ���
	hServiceDDK = OpenService( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );  

	if( hServiceDDK == NULL )  
	{
		//����������Ӧ�ķ���ʧ��
		printf( "OpenService() Failed %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{  
		printf( "OpenService() ok ! \n" );  
	}  
	//ֹͣ�����������ֹͣʧ�ܣ�ֻ�������������ܣ��ٶ�̬���ء�  
	if( !ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) )  
	{  
		printf( "ControlService() Failed %d !\n", GetLastError() );  
	}  
	else  
	{
		//����������Ӧ��ʧ��
		printf( "ControlService() ok !\n" );  
	}  
	//��̬ж����������  
	if( !DeleteService( hServiceDDK ) )  
	{
		//ж��ʧ��
		printf( "DeleteSrevice() Failed %d !\n", GetLastError() );  
	}  
	else  
	{  
		//ж�سɹ�
		printf( "DelServer:eleteSrevice() ok !\n" );  
	}  
	bRet = TRUE;
BeforeLeave:
//�뿪ǰ�رմ򿪵ľ��
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
	//������������  
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
 
	m_procListCtrl.InsertColumn(2,"ӳ��λ��������",LVCFMT_LEFT,700);  

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
		MessageBox("��ѡ�����");
		return;
	}
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 
								FALSE, m_dwPID);
	if(process!=NULL)
	{
	GetExitCodeProcess(process,&dw); 
	TerminateProcess(process,dw);
	MessageBox(_T("�����ѱ���ֹ"),_T("��ֹ����"),MB_OK);
	}
	else
		MessageBox(_T("������ֹʧ��"),_T("��ֹ����"),MB_OK);	
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
    CMenu menu , *pSubMenu;//��������Ҫ�õ���cmenu����
	
    menu.LoadMenu(IDR_RIGHT);//װ���Զ�����Ҽ��˵�
    pSubMenu = menu.GetSubMenu(0);//��ȡ��һ�������˵������Ե�һ���˵��������Ӳ˵�
    CPoint oPoint;//����һ������ȷ�����λ�õ�λ��
    GetCursorPos( &oPoint);//��ȡ��ǰ����λ�ã��Ա�ʹ�ò˵����Ը�����

    int istat=m_procListCtrl.GetSelectionMark();//��istat��ŵ�ǰѡ�����ǵڼ���
    m_strSearch =m_procListCtrl.GetItemText(istat,1);//��ȡ��ǰ���е����ݣ�0�����ǵ�0��
	m_dwPID = (pid=atol(m_procListCtrl.GetItemText(istat,0)))>0?pid:-1;
    pSubMenu->TrackPopupMenu (TPM_LEFTALIGN, oPoint.x, oPoint.y, this); //��ָ��λ����ʾ�����˵�

	*pResult = 0;	
}

void CLstProcDlg::OnForceKillproc() 
{
	DWORD ret = 0;
	DWORD read;
	if(m_dwPID==-1)
	{
		MessageBox("��ѡ�����");
		return;
	}
	if(MessageBox(_T("ǿɱ���̿��ܻ����ϵͳ���ȶ���ȷ��Ҫ������"),_T("ǿɱ����"),MB_YESNO)==IDYES)
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
			MessageBox(_T("�ɹ�ִ��"));
		else
			MessageBox(_T("ִ��ʧ��"));
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
		MessageBox(_T("��������ʧ��"), _T("Error"), MB_OK);
		return FALSE;
	}
	
	
	gh_Device = OpenDevice();
	if (gh_Device == NULL)
	{
		MessageBox(_T("���豸ʧ��"), _T("Error"), MB_OK);
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
		MessageBox("��ѡ�����");
		return;
	}
	if(MessageBox(_T("ȷ��Ҫ���б�����"),_T("��������"),MB_YESNO)==IDYES)
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
			MessageBox(_T("�����ɹ�ִ��"));
		else
			MessageBox(_T("����ִ��ʧ��"));
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
