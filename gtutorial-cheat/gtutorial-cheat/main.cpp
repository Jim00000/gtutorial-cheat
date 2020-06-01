#include "Step1.h"
#include <iostream>

int main()
{
	using namespace GTutorial::Helper;
	using namespace GTutorial::Step1;

	LPCWSTR procName = L"gtutorial-x86_64.exe";
	DWORD processId = GetProcessIdByName(procName);

	if (processId == 0) {
		std::cerr << "Can not find the process \"gtutorial-x86_64.exe\"" << std::endl;
		return EXIT_FAILURE;
	}

	PBYTE baseAddr = NULL;
	DWORD baseSize = 0;
	if (GetProcessBaseAddr(processId, baseAddr, baseSize)) {
		std::cout << "Process Id   : " << processId << std::endl;
		std::cout << "Base Address : " << reinterpret_cast<void*>(baseAddr) << std::endl;
		std::cout << "Base Size    : " << std::hex << baseSize << std::endl;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	if (hProcess == NULL) {
		CheckLastError();
		exit(EXIT_FAILURE);
	}

	std::cout << "ShootCounter : " << ReadShootCounter(hProcess, baseAddr) << std::endl;

	PatchInfiniteAmmo(hProcess, baseAddr, baseSize);

	CloseHandle(hProcess);
	system("pause");

	return EXIT_SUCCESS;
}
