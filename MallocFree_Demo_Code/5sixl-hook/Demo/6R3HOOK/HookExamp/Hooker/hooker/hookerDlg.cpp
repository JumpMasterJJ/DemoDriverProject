// hookerDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "hooker.h"
#include "hookerDlg.h"
#include <tchar.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// ChookerDlg 对话框




ChookerDlg::ChookerDlg(CWnd* pParent /*=NULL*/)
	: CDialog(ChookerDlg::IDD, pParent)
	, m_dwPid(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void ChookerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_PID, m_dwPid);
}

BEGIN_MESSAGE_MAP(ChookerDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDOK, &ChookerDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// ChookerDlg 消息处理程序

BOOL ChookerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void ChookerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void ChookerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR ChookerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL AddDebugPrivilege(void)
{

	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hToken;

	if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&luid))
	{
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid=luid;
	tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
	if(!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		return FALSE;
	}
	if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,(PDWORD)NULL))
	{
		return FALSE;
	}
	return TRUE;
} 

int InjectDll( HANDLE hProcess, TCHAR* szLibPath)
{
	HANDLE hThread;
	void*  pLibRemote = 0;
	DWORD  hLibModule = 0;
	HMODULE hKernel32 = ::GetModuleHandle(_T("Kernel32"));

	LPTHREAD_START_ROUTINE pLoadFunc = NULL;

	pLoadFunc = (LPTHREAD_START_ROUTINE) ::GetProcAddress(hKernel32,"LoadLibraryW");

	if (szLibPath == NULL ||
		hProcess == NULL ||
		pLoadFunc == NULL)
	{
		return FALSE;
	}
	pLibRemote = ::VirtualAllocEx( hProcess, NULL, (_tcslen(szLibPath) + 1)*sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE );
	if( pLibRemote == NULL )
		return false;
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath,(_tcslen(szLibPath) + 1)*sizeof(TCHAR),NULL);

	hThread = ::CreateRemoteThread( hProcess, NULL, 0,(LPTHREAD_START_ROUTINE)pLoadFunc, 
		pLibRemote, 0, NULL );
	if( hThread == NULL )
		goto JUMP;
	DWORD dwError = GetLastError();
	::WaitForSingleObject( hThread, INFINITE );
	dwError = GetLastError();
	::GetExitCodeThread( hThread, &hLibModule );

	::CloseHandle( hThread );

JUMP:	
	::VirtualFreeEx( hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE );
	if( hLibModule == NULL )
		return false;
	return hLibModule;
}


void ChookerDlg::OnBnClickedOk()
{

	//LoadLibraryW(_T("hookdll.dll"));
	AddDebugPrivilege();
	UpdateData(TRUE);

	//MessageBox(_T("Failed"));

	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | 
		PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE  | 
		PROCESS_VM_READ,FALSE, m_dwPid);
	if (hProcess == NULL)
	{
		MessageBox(_T("Failed"));
		return;
	}

	InjectDll(hProcess, _T("hookdll.dll"));

	//(CButton*)GetDlgItem(IDOK)->EnableWindow(FALSE);
	//OnOK();
}
