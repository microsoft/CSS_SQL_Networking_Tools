#pragma once
#include "afxwin.h"

/////////////////////////////////////////////////////////////////////////////
// CSSPIClientDlg dialog

class CSSPIClientDlg : public CDialog
{
// Construction
public:
	CSSPIClientDlg(CWnd* pParent = NULL);	// standard constructor
	BSTR bstrSPN;
// Dialog Data
	//{{AFX_DATA(CSSPIClientDlg)
	enum { IDD = IDD_SSPICLIENT_DIALOG };
	CString	m_strConnect;
	CString	m_strLogFile;
	BOOL m_fUseIntegrated;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSSPIClientDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CSSPIClientDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnBtnConnect();
	afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnConnect2();
	
	afx_msg void OnBnClickedCheck1();
	CString m_strPassword;
	CString m_strUserId;
	BOOL m_fEncryptionTest;
	afx_msg void OnBnClickedBtnConnect3();
	afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	afx_msg void OnSysKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	BOOL m_fUseSQLNCLI;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.