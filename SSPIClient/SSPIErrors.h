#pragma once

#define E_SSPI_BASE_ERROR (HRESULT)0x80040200L

// Failed to load secur32.dll
#define E_SSPI_SECUR32_MODULE_LOAD_FAILURE	(E_SSPI_BASE_ERROR+1)

// Failed to load crypt32.dll
#define E_SSPI_CRYPT32_MODULE_LOAD_FAILURE	(E_SSPI_BASE_ERROR+2)

// Failed to load dbnetlib.dll
#define E_SSPI_DBNETLIB_MODULE_LOAD_FAILURE	(E_SSPI_BASE_ERROR+3)

// Failed to load ssnetlib.dll.
#define E_SSPI_SSNETLIB_MODULE_LOAD_FAILURE	(E_SSPI_BASE_ERROR+4)

// Successfully loaded dll but could not load function in dll.
#define E_SSPI_FUNCTION_LOAD_FAILURE		(E_SSPI_BASE_ERROR+5)

// Attempt to start detouring after detouring is already started.
#define E_SSPI_DETOUR_RESTART_FAILURE		(E_SSPI_BASE_ERROR+6)

// Attempt to stop detouring when detouring is not started.
#define E_SSPI_DETOUR_STOP_FAILURE			(E_SSPI_BASE_ERROR+7)

// Failed to open log file.
#define E_SSPI_LOG_FILE_OPEN_FAILURE		(E_SSPI_BASE_ERROR+8)