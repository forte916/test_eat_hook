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

fp_LoadLibraryA orig_LoadLibraryA = NULL;
fp_PeekMessageA orig_PeekMessageA = NULL;

HMODULE WINAPI hook_LoadLibraryA(LPCSTR lpLibFileName)
{
	printf("hook_LoadLibraryA: %s \n", lpLibFileName);
	return orig_LoadLibraryA(lpLibFileName);
}

BOOL WINAPI hook_PeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
	printf("hook_PeekMessageA: 0x%p \n", lpMsg);
	return orig_PeekMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}


/**
 * @brief  Overwrite 4 bytes at destAddr by given newOffset
 * @param  destAddr: An address where overwritten
 * @param  newValue: A new value
 * @return TRUE on success, otherwise FALSE
 */
int forceWrite4(DWORD* destAddr, DWORD newValue)
{
	DWORD oldProtect;
	if (VirtualProtect(destAddr, sizeof(DWORD), PAGE_READWRITE, &oldProtect)) {
		*destAddr = newValue;
		VirtualProtect(destAddr, sizeof(DWORD), oldProtect, &oldProtect);
		FlushInstructionCache(GetCurrentProcess(), destAddr, sizeof(DWORD));
		return TRUE;
	}
	return FALSE;
}

/**
 * @brief  Replace target function by hook function by writing IAT.
 * @param  modName: A module name. If NULL, hook calling process(.exe file)
 * @param  targetName: A function name to be replaced
 * @param  hookFunc: An address of replacement function
 * @param  origFunc: __out An original functions address to be set
 * @return TRUE on success, otherwise FALSE
 */
int hookIATwithName(const char *modName, const char *targetName, DWORD hookFunc, DWORD* origFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDesc   = NULL;
	PIMAGE_THUNK_DATA         pNameTable    = NULL;
	PIMAGE_THUNK_DATA         pAddressTable = NULL;
	PIMAGE_IMPORT_BY_NAME     pImportByName = NULL;
	DWORD* pImportedAddr = 0;
	char*  importedName  = NULL;

	hMod = GetModuleHandleA(modName);
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToData((PVOID) hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

	if (pImportDesc == NULL) {
		printf("ERROR: Import Directory not found\n");
		return FALSE;
	}

	// Repeat a count of DLLs
	while (pImportDesc->Name) {
		char* dllName = (char *) ((DWORD) hMod + pImportDesc->Name);
		//printf("%s: \n", dllName);

		pNameTable    = (PIMAGE_THUNK_DATA) ((DWORD) hMod + pImportDesc->OriginalFirstThunk);
		pAddressTable = (PIMAGE_THUNK_DATA) ((DWORD) hMod + pImportDesc->FirstThunk);

		//Repeat a count of functions
		while (pNameTable->u1.Function) {
			pImportedAddr = &(pAddressTable->u1.Function);
			//printf("imported: 0x%x, IAT addr: 0x%x, func first4: 0x%x \n", 
			//		*pImportedAddr, pImportedAddr, *((DWORD *) *pImportedAddr));

			if (pNameTable->u1.AddressOfData & 0x80000000) {
				// シンボルが序数情報の場合
				DWORD dwOrd = pNameTable->u1.AddressOfData ^ 0x80000000;
				printf("Ordinal %d (0x%x)\n", dwOrd, dwOrd);
			} else {
				// シンボルが名前情報の場合
				pImportByName = (PIMAGE_IMPORT_BY_NAME) ((DWORD) hMod + pNameTable->u1.AddressOfData);
				importedName = (char *) (pImportByName->Name);
				//printf("[%s]\n", importedName);

				if (_stricmp(targetName, importedName) == 0) {
					printf("%s: imported: 0x%x, IAT addr: 0x%x, func first4: 0x%x \n", 
							importedName, *pImportedAddr, pImportedAddr, *((DWORD *) *pImportedAddr));
					goto install_hook;
				}
			}
			pNameTable++;
			pAddressTable++;
		}
    	pImportDesc++;
	}
	return FALSE;

install_hook:
	if (pImportedAddr != 0 && hookFunc != NULL) {
		*origFunc = *pImportedAddr;
		forceWrite4(pImportedAddr, hookFunc);
	}
	return TRUE;
}


/**
 * @brief  Replace target function by hook function by writing IAT.
 * @param  modName: A module name. If NULL, hook calling process(.exe file)
 * @param  targetFunc: An address of function to be replaced
 * @param  hookFunc: An address of replacement function
 * @param  origFunc: __out An original functions address to be set
 * @return TRUE on success, otherwise FALSE
 */
int hookIATwithAddress(const char *modName, DWORD targetFunc, DWORD hookFunc, DWORD* origFunc)
{
	HMODULE hMod = NULL;
	ULONG   size = 0;
	PIMAGE_IMPORT_DESCRIPTOR  pImportDesc   = NULL;
	PIMAGE_THUNK_DATA         pNameTable    = NULL;
	PIMAGE_THUNK_DATA         pAddressTable = NULL;
	PIMAGE_IMPORT_BY_NAME     pImportByName = NULL;
	DWORD* pImportedAddr = 0;
	char*  importedName  = NULL;

	hMod = GetModuleHandleA(modName);
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToData((PVOID) hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

	if (pImportDesc == NULL) {
		printf("ERROR: Import Directory not found\n");
		return FALSE;
	}

	// Repeat a count of DLLs
	while (pImportDesc->Name) {
		char* dllName = (char *) ((DWORD) hMod + pImportDesc->Name);
		//printf("%s: \n", dllName);

		pNameTable    = (PIMAGE_THUNK_DATA) ((DWORD) hMod + pImportDesc->OriginalFirstThunk);
		pAddressTable = (PIMAGE_THUNK_DATA) ((DWORD) hMod + pImportDesc->FirstThunk);

		//Repeat a count of functions
		while (pAddressTable->u1.Function) {
			pImportedAddr = &(pAddressTable->u1.Function);
			//printf("imported: 0x%x, IAT addr: 0x%x, func first4: 0x%x \n", 
			//		*pImportedAddr, pImportedAddr, *((DWORD *) *pImportedAddr));

			if (*pImportedAddr == targetFunc) {
				printf("--: imported: 0x%x, IAT addr: 0x%x, func first4: 0x%x \n", 
						*pImportedAddr, pImportedAddr, *((DWORD *) *pImportedAddr));
				goto install_hook;
			}
			pNameTable++;
			pAddressTable++;
		}
    	pImportDesc++;
	}
	return FALSE;

install_hook:
	if (pImportedAddr != 0 && hookFunc != NULL) {
		*origFunc = *pImportedAddr;
		forceWrite4(pImportedAddr, hookFunc);
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

	//// Hook LoadLibraryA
	printf("%s: direct  : 0x%x, orig: 0x%x, hookFunc: 0x%x \n", "LoadLibraryA", (DWORD) LoadLibraryA, (DWORD) orig_LoadLibraryA, (DWORD) hook_LoadLibraryA);
	hookIATwithName(NULL, "LoadLibraryA", (DWORD) hook_LoadLibraryA, (DWORD *) &orig_LoadLibraryA);
	printf("%s: direct  : 0x%x, orig: 0x%x, orig first4: 0x%x \n", "LoadLibraryA", (DWORD) LoadLibraryA, (DWORD) orig_LoadLibraryA, *((DWORD *) orig_LoadLibraryA));

	LoadLibraryA("user32.dll");

	//// Hook PeekMessageA
	printf("%s: direct  : 0x%x, orig: 0x%x, hookFunc: 0x%x \n", "PeekMessageA", (DWORD) PeekMessageA, (DWORD) orig_PeekMessageA, (DWORD) hook_PeekMessageA);
	//hookIATwithName(NULL, "PeekMessageA", (DWORD) hook_PeekMessageA, (DWORD *) &orig_PeekMessageA);
	hookIATwithAddress(NULL, (DWORD) PeekMessageA, (DWORD) hook_PeekMessageA, (DWORD *) &orig_PeekMessageA);
	printf("%s: direct  : 0x%x, orig: 0x%x, orig first4: 0x%x \n", "PeekMessageA", (DWORD) PeekMessageA, (DWORD) orig_PeekMessageA, *((DWORD *) orig_PeekMessageA));

	PeekMessageA(NULL, NULL, 0, 0, 0);

    return 0;
}

