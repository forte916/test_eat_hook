// test_iat_hook.cpp : アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"
#include "windows.h"
#include "imagehlp.h"  //ImageDirectoryEntryToData

typedef HMODULE (WINAPI* fp_LoadLibraryA) (
    _In_ LPCSTR lpLibFileName);

typedef BOOL (WINAPI* fp_PeekMessageA) (
    _Out_ LPMSG lpMsg,
    _In_opt_ HWND hWnd,
    _In_ UINT wMsgFilterMin,
    _In_ UINT wMsgFilterMax,
    _In_ UINT wRemoveMsg);


HMODULE WINAPI hook_LoadLibraryA(LPCSTR lpLibFileName)
{
	printf("hook_LoadLibraryA: %s \n", lpLibFileName);
	return LoadLibraryA(lpLibFileName);
}

BOOL WINAPI hook_PeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
	printf("hook_PeekMessageA: 0x%p \n", lpMsg);
	return PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}


/**
 * @brief  Overwrite 4 bytes at destAddr by given newOffset
 * @param  destAddr: An address where overwritten
 * @param  newOffset: A new value
 * @return TRUE on success, otherwise FALSE
 */
int forceWrite4(DWORD* destAddr, DWORD newOffset)
{
	DWORD oldProtect;
	VirtualProtect(destAddr, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
	*destAddr = newOffset;
	VirtualProtect(destAddr, sizeof(DWORD), oldProtect, &oldProtect);
	return TRUE;
}

/**
 * @brief  Replace target function by hook function by writing EAT.
 * @param  modName: A module name
 * @param  targetName: A function name to be replaced
 * @param  hookFunc: An address of replacement function
 * @return TRUE on success, otherwise FALSE
 */
int hookEATwithName(const char *modName, const char *targetName, DWORD hookFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD*  pAddressTable = NULL;
	DWORD*  pNameTable = NULL;
	 WORD*  pOrdinalTable = NULL;
	DWORD   i = 0;
	DWORD* pRelativeOffset = 0;
	DWORD  exportedAddr = 0;
	char*  exportedName = NULL;

	hMod = GetModuleHandleA(modName);
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData((PVOID) hMod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

	if (pExportDirectory == NULL) {
		printf("ERROR: Export Directory not found\n");
		return FALSE;
	}

	pAddressTable = (DWORD*) ((DWORD) hMod + pExportDirectory->AddressOfFunctions);
	pNameTable    = (DWORD*) ((DWORD) hMod + pExportDirectory->AddressOfNames);
	pOrdinalTable = ( WORD*) ((DWORD) hMod + pExportDirectory->AddressOfNameOrdinals);

	for (i=0; i < pExportDirectory->NumberOfFunctions; i++) {
		exportedName = (char*) ((DWORD) hMod + pNameTable[i]);
		//printf("%d: %s\n", i, exportedName);
		if (_stricmp(targetName, exportedName) == 0) {
			pRelativeOffset = &pAddressTable[pOrdinalTable[i]];
			exportedAddr = (DWORD) hMod + *pRelativeOffset;
			printf("%s: exported: 0x%x, offset: 0x%x, hMod: 0x%x, EAT addr: 0x%x \n",
					exportedName, exportedAddr, *pRelativeOffset, hMod, pRelativeOffset);
			break;
		}
	}

	if (pRelativeOffset != 0 && hookFunc != NULL) {
		DWORD newOffset = hookFunc - (DWORD) hMod;
		printf("%s: relative: 0x%x, oldOffset: 0x%x, newOffset: 0x%x \n", exportedName, pRelativeOffset, *pRelativeOffset, newOffset);

		forceWrite4(pRelativeOffset, newOffset);
	}
	return TRUE;
}


/**
 * @brief  Replace target function by hook function by writing EAT.
 * @param  modName: A module name
 * @param  targetFunc: An address of function to be replaced
 * @param  hookFunc: An address of replacement function
 * @return TRUE on success, otherwise FALSE
 */
int hookEATwithAddress(const char *modName, DWORD targetFunc, DWORD hookFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD*  pAddressTable = NULL;
	DWORD*  pNameTable = NULL;
	 WORD*  pOrdinalTable = NULL;
	DWORD   i = 0;
	DWORD* pRelativeOffset = 0;
	DWORD  exportedAddr = 0;
	char*  exportedName = NULL;

	hMod = GetModuleHandleA(modName);
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData((PVOID) hMod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

	if (pExportDirectory == NULL) {
		printf("ERROR: Export Directory not found\n");
		return FALSE;
	}

	pAddressTable = (DWORD*) ((DWORD) hMod + pExportDirectory->AddressOfFunctions);
	pNameTable    = (DWORD*) ((DWORD) hMod + pExportDirectory->AddressOfNames);
	pOrdinalTable = ( WORD*) ((DWORD) hMod + pExportDirectory->AddressOfNameOrdinals);

	for (i=0; i < pExportDirectory->NumberOfFunctions; i++) {
		exportedName = (char*) ((DWORD) hMod + pNameTable[i]);

		pRelativeOffset = &pAddressTable[pOrdinalTable[i]];
		exportedAddr = (DWORD) hMod + *pRelativeOffset;
		if (exportedAddr == targetFunc) {
			//printf("%d: %s\n", i, exportedName);
			printf("%s: exported: 0x%x, offset: 0x%x, hMod: 0x%x, EAT addr: 0x%x \n",
					exportedName, exportedAddr, *pRelativeOffset, hMod, pRelativeOffset);
			break;
		}
	}

	if (pRelativeOffset != 0 && hookFunc != NULL) {
		DWORD newOffset = hookFunc - (DWORD) hMod;
		printf("%s: relative: 0x%x, oldOffset: 0x%x, newOffset: 0x%x \n", exportedName, pRelativeOffset, *pRelativeOffset, newOffset);

		forceWrite4(pRelativeOffset, newOffset);
	}
	return TRUE;
}


/**
 * @brief  Return an address of given apiName.
 * @param  modName: A module name
 * @param  apiName: An api name
 * @return An address of apiName
 */
DWORD getApiAddress(const char *modName, const char *apiName)
{
	HMODULE hMod;
	hMod = GetModuleHandleA(modName);
	FARPROC fproc = GetProcAddress(hMod, apiName);

	printf("%s: get proc: 0x%x, hMod: 0x%x \n", apiName, fproc, hMod);
	return (DWORD) fproc;
}

int main()
{
	printf("Hello World.\n");

	printf("%s: direct  : 0x%x, hookFunc: 0x%x \n", "LoadLibraryA", (DWORD) LoadLibraryA, (DWORD) hook_LoadLibraryA);
	hookEATwithName("kernel32.dll", "LoadLibraryA", (DWORD) hook_LoadLibraryA);
	fp_LoadLibraryA fp = (fp_LoadLibraryA) getApiAddress("kernel32.dll", "LoadLibraryA");
	fp("kernel32.dll");

	LoadLibraryA("user32.dll");

	printf("%s: direct  : 0x%x, hookFunc: 0x%x \n", "PeekMessageA", (DWORD) PeekMessageA, (DWORD) hook_PeekMessageA);
	//hookEATwithName("user32.dll", "PeekMessageA", (DWORD) hook_PeekMessageA);
	hookEATwithAddress("user32.dll", (DWORD) PeekMessageA, (DWORD) hook_PeekMessageA);
	fp_PeekMessageA fp2 = (fp_PeekMessageA) getApiAddress("user32.dll", "PeekMessageA");
	fp2(NULL, NULL, 0, 0, 0);

    return 0;
}

