#include "CheatingHelper.h"

#include <tlhelp32.h>
#include "spdlog_wrapper.h"

VOID GTutorial::Helper::CheckLastError()
{
	LPSTR lpMsgBuf;

	SIZE_T size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&lpMsgBuf,
		0,
		NULL
	);

	std::string message(lpMsgBuf, size);
	LocalFree(lpMsgBuf);
	spdlog::error(message);
}

BOOL GTutorial::Helper::GetProcessBaseAddr(DWORD pid, LPBYTE& baseAddr, DWORD& baseSize) {

	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, pid);
	
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		CheckLastError();
		return FALSE;
	}

	// Designated initializers
	MODULEENTRY32W modEntry = {
		.dwSize = sizeof(MODULEENTRY32W)
	};

	if (Module32First(hSnapshot, &modEntry) && GetLastError() != ERROR_NO_MORE_FILES) {
		baseAddr = modEntry.modBaseAddr;
		baseSize = modEntry.modBaseSize;
	}

	CloseHandle(hSnapshot);

	return TRUE;
}

DWORD GTutorial::Helper::GetProcessIdByName(LPCWSTR procName)
{
	DWORD procId = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		CheckLastError();
		return FALSE;
	}

	PROCESSENTRY32W procEntry = {
		.dwSize = sizeof(PROCESSENTRY32W)
	};

	if (Process32FirstW(hSnapshot, &procEntry)) {
		while (Process32Next(hSnapshot, &procEntry) && GetLastError() != ERROR_NO_MORE_FILES) {
			if (wcscmp(procName, procEntry.szExeFile) == 0) {
				procId = procEntry.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle(hSnapshot);
	return procId;
}

DWORD64 GTutorial::Helper::AOBScan(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize, LPCBYTE victim, SIZE_T victimSz)
{
	using namespace GTutorial::Helper;

	DWORD64 victimAddr = NULL;
	LPBYTE buffer = new BYTE[baseSize];
	ZeroMemory(buffer, baseSize);

	if (ReadProcessMemory(hProcess, baseAddr, buffer, baseSize, NULL) == 0) {
		CheckLastError();
		delete[] buffer;
		exit(EXIT_FAILURE);
	}

	for (SIZE_T i = 0; i < baseSize - victimSz; i++) {
		if (memcmp(&buffer[i], victim, victimSz) == 0) {
			victimAddr = reinterpret_cast<DWORD64>(baseAddr + i);
			break;
		}
	}

	delete[] buffer;
	return victimAddr;
}

LPVOID GTutorial::Helper::NewMemoryBlock(HANDLE hProcess, SIZE_T size)
{
	LPVOID newPage = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (newPage == NULL) {
		CheckLastError();
	}

	return newPage;
}

BOOL GTutorial::Helper::FreeMemoryBlock(HANDLE hProcess, LPVOID lpAddress)
{
	if (VirtualFreeEx(hProcess, lpAddress, 0, MEM_RELEASE) == 0) {
		CheckLastError();
		return FALSE;
	}

	return TRUE;
}