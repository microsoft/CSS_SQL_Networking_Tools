// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//
// Written by the Microsoft CSS SQL Networking Team
//

#include "stdafx.h"
#include "FileInfo.h"


// Library needed for VerQueryValue in GetFileInfo helper function.
#pragma comment(lib,"version.lib")

const char* GetSystemFolder(void)
{
	static char szFolder[ MAX_PATH ] = { 0 };
	if ( '\0' != szFolder[0] ) return szFolder;
	::GetSystemDirectory( szFolder, sizeof(szFolder) );
	strcat_s( szFolder, sizeof(szFolder), "\\" );
	_strlwr_s( szFolder, sizeof(szFolder));
	return szFolder;
}

void GetCommonFilesFolder( char* pszFolder, size_t cchFolder )
{
	HKEY hKey;
	DWORD dwRC, dwType; 
	ULONG ulCFLength = MAX_PATH;

	strcpy_s( pszFolder, cchFolder, "c:\\program files\\common files" );

	// Open HLM\SOFTWARE\Microsoft\Windows\CurrentVersion registry key.
	dwRC = ::RegOpenKeyEx( HKEY_LOCAL_MACHINE, 
						   "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 
						   0, 
						   KEY_READ, 
						   &hKey );

	if ( dwRC ) return;

	// Read CommonFilesDir registry string value.
	dwRC = ::RegQueryValueEx( hKey, 
						      "CommonFilesDir", 
						      0, 
						      &dwType, 
						      (UCHAR*)pszFolder, 
						      &ulCFLength );

	::RegCloseKey( hKey );

}

const char* GetADOFolder(void)
{
	static char szFolder[ MAX_PATH ] = { 0 };
	if ( '\0' != szFolder[0] ) return szFolder;
	GetCommonFilesFolder( szFolder, sizeof(szFolder) );
	strcat_s( szFolder, sizeof(szFolder), "\\system\\ado\\" );
	_strlwr_s( szFolder, sizeof(szFolder) );
	return szFolder;
}

const char* GetOLEDBFolder(void)
{
	static char szFolder[ MAX_PATH ] = { 0 };
	if ( '\0' != szFolder[0] ) return szFolder;
	GetCommonFilesFolder( szFolder, sizeof(szFolder) );
	strcat_s( szFolder, sizeof(szFolder), "\\system\\ole db\\" );
	_strlwr_s( szFolder, sizeof(szFolder));
	return szFolder;
}

// Helper macro for GetFileVersion.
#define VQV( QS ) \
	if ( VerQueryValue( pVerInfo, QS, (LPVOID*) &pszReturnString, &cbReturn ) ) \
	{	\
		strcpy_s( szVersionInfo, sizeof(szVersionInfo), pszReturnString ); \
		goto GetFileVersionExit; \
	} 

const char* GetFileVersion( const char* pszFileName )
{
	static char szVersionInfo[ MAX_PATH ];
	DWORD dwVerInfoSize;
	PBYTE pVerInfo = NULL;
	PSTR pszReturnString = NULL;
	UINT cbReturn;
	char* s;

	::ZeroMemory( szVersionInfo, sizeof(szVersionInfo) );

	// Get version information size
	dwVerInfoSize = GetFileVersionInfoSize( (char*)pszFileName, NULL );

	if ( !dwVerInfoSize ) goto GetFileVersionExit;

	// Allocate space to hold the file version info.
	pVerInfo = new BYTE[dwVerInfoSize];

	if ( !pVerInfo ) goto GetFileVersionExit;

	if ( !GetFileVersionInfo( (char*) pszFileName, 0, dwVerInfoSize, pVerInfo ) ) goto GetFileVersionExit;

	// Try various code pages and language settings.
	// A little hacky but effective for the occasional DLL
	// with the quirky codepage and language setting.
	VQV( "\\StringFileInfo\\000004E4\\FileVersion" );
	VQV( "\\StringFileInfo\\040904E4\\FileVersion" );
	VQV( "\\StringFileInfo\\00000000\\FileVersion" );
	VQV( "\\StringFileInfo\\000004B0\\FileVersion" );
	VQV( "\\StringFileInfo\\04090000\\FileVersion" );
	VQV( "\\StringFileInfo\\040904B0\\FileVersion" );
		
GetFileVersionExit:

	// Clean up pVerInfo and return string.
	if ( pVerInfo ) delete [] pVerInfo;

	// Trim leading spaces.
	while ( ' ' == szVersionInfo[0] )
	{
		s = szVersionInfo;
		while ( '\0' != *s )
		{
			*s = *(s+1);
			s++;
		}
	}

	return szVersionInfo;

}