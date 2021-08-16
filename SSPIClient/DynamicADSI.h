#pragma once

struct __declspec(uuid("001677d0-fd16-11ce-abc4-02608c9e7553")) guid_IID_IADsContainer;
struct __declspec(uuid("109ba8ec-92f0-11d0-a790-00c04fd8d5a8")) guid_IID_IDirectorySearch;

BOOL LoadADSI();
HRESULT GetGCIADsContainer( IADsContainer** ppContainer );
