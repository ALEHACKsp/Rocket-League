#include "Signatures.h"
#include "Logging.h"

DWORD64 dwSignatures[NumSigs] = { 0 };

bool bDataCompare(const BYTE *pData, const BYTE *bMask, const char *szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask) if (*szMask == 'x' && *pData != *bMask) return false;
	return (*szMask) == NULL;
}

DWORD64 dwFindPattern(DWORD64 dwAddress, DWORD dwLen, BYTE *bMask, char *szMask)
{
	for (DWORD i = 0; i < dwLen; i++) if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask)) return (DWORD64)(dwAddress + i);
	return 0;
}

void LoadSignatures()
{
	DWORD64 ModuleAddress = (DWORD64)GetModuleHandle(0) + 0x1000;
	 
	dwSignatures[0] = dwFindPattern(ModuleAddress, 0x1000000, (BYTE*)"\x48\x8B\x05\x00\x00\x00\x00\x48\x63\xCB\x48\x89", "xxx????xxxx");

	dwSignatures[1] = dwFindPattern(ModuleAddress, 0x1000000, (BYTE*)"\x48\x89\x05\x00\x00\x00\x00\x41\x89", "xxx????xx");
	

	for (int i = 0; i < NumSigs; i++) if (dwSignatures[i] == 0)
	{
		#ifdef Logging
		LogSignatures();
		#endif
		exit(0); 
	}

}

#ifdef Logging
void LogSignatures()
{
	for (int i = 0; i < NumSigs; i++) add_log("%i: 0x%x", i, dwSignatures[i]);
}
#endif


