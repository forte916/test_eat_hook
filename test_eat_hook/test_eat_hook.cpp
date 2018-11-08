// test_iat_hook.cpp : アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"
#include "windows.h"
#include "imagehlp.h"  //ImageDirectoryEntryToData


int hookEAT(DWORD* destAddr, DWORD newOffset)
{
    DWORD oldProtect;
    VirtualProtect(destAddr, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
    *destAddr = newOffset;
    VirtualProtect(destAddr, sizeof(DWORD), oldProtect, &oldProtect);
	return TRUE;
}

void showEATAddress(const char *modName, const char *apiName, DWORD apiAddr)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD*  pAddressTable = NULL;
	DWORD*  pNameTable = NULL;
	 WORD*  pOrdinalTable = NULL;
	DWORD   i = 0;
	DWORD   relativeOffset = 0;

	hMod = GetModuleHandleA(modName);
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData((PVOID)hMod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

	if (pExportDirectory == NULL) {
		printf("ERROR: Export Directory not found");
		return;
	}

	pAddressTable = (DWORD*) ((DWORD) hMod + pExportDirectory->AddressOfFunctions);
	pNameTable    = (DWORD*) ((DWORD) hMod + pExportDirectory->AddressOfNames);
	pOrdinalTable = ( WORD*) ((DWORD) hMod + pExportDirectory->AddressOfNameOrdinals);

	for (i=0; i < pExportDirectory->NumberOfFunctions; i++) {
		char* exportedName = (char*) ((DWORD) hMod + pNameTable[i]);
		//printf("exportedName: %s\n", exportedName);
		if (_stricmp(apiName, exportedName) == 0) {
			relativeOffset = pAddressTable[pOrdinalTable[i]];
			DWORD* pRelativeOffset = &pAddressTable[pOrdinalTable[i]];
			DWORD* pExportedAddr = (DWORD*) ((DWORD) hMod + relativeOffset);
			printf("%s: exported: 0x%x, offset: 0x%x, hMod: 0x%x, pRelativeOffset: 0x%x, offset2: 0x%x \n", apiName, pExportedAddr, relativeOffset, hMod, pRelativeOffset, *pRelativeOffset);
			printf("%s: direct  : 0x%x\n", apiName, apiAddr);
			break;
		}
	}
	return;
}


void showApiAddress(const char *modName, const char *apiName, DWORD apiAddr)
{
	HMODULE hMod;
	hMod = GetModuleHandleA(modName);
	FARPROC fproc = GetProcAddress(hMod, apiName);

	printf("%s: get proc: 0x%x, hMod: 0x%x\n", apiName, fproc, hMod);
	printf("%s: direct  : 0x%x\n", apiName, apiAddr);
}

int main()
{
	printf("Hello World.\n");

	showApiAddress("kernel32.dll", "LoadLibraryA", (DWORD)LoadLibraryA);
	LoadLibraryA("user32.dll");
	showApiAddress("user32.dll", "PeekMessageA", (DWORD)PeekMessageA);

	showEATAddress("kernel32.dll", "LoadLibraryA", (DWORD)LoadLibraryA);
	showEATAddress("user32.dll", "PeekMessageA", (DWORD)PeekMessageA);

    return 0;
}

