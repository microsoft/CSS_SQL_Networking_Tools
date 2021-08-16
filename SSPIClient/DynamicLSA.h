#pragma once

void LoadLSA();

typedef NTSTATUS (NTAPI * LsaLookupAuthenticationPackage_FN)
    (
    IN HANDLE LsaHandle,
    IN PLSA_STRING PackageName,
    OUT PULONG AuthenticationPackage
    );

typedef NTSTATUS (NTAPI * LsaFreeReturnBuffer_FN)
    (
    IN PVOID Buffer
    );

typedef NTSTATUS (NTAPI * LsaCallAuthenticationPackage_FN)
   (
    IN HANDLE LsaHandle,
    IN ULONG AuthenticationPackage,
    IN PVOID ProtocolSubmitBuffer,
    IN ULONG SubmitBufferLength,
    OUT PVOID *ProtocolReturnBuffer,
    OUT PULONG ReturnBufferLength,
    OUT PNTSTATUS ProtocolStatus
    );

typedef NTSTATUS (NTAPI * LsaDeregisterLogonProcess_FN)
    (
    IN HANDLE LsaHandle
    );

typedef NTSTATUS (NTAPI * LsaConnectUntrusted_FN)
    (
    OUT PHANDLE LsaHandle
    );

extern BOOL g_fKerberosLoaded;
extern LsaLookupAuthenticationPackage_FN pfnLsaLookupAuthenticationPackage;
extern LsaFreeReturnBuffer_FN pfnLsaFreeReturnBuffer;
extern LsaCallAuthenticationPackage_FN pfnLsaCallAuthenticationPackage;
extern LsaDeregisterLogonProcess_FN pfnLsaDeregisterLogonProcess;
extern LsaConnectUntrusted_FN pfnLsaConnectUntrusted;