#include "Step1.h"
#include "spdlog_wrapper.h"

int main()
{
	using namespace GTutorial::Helper;
	using namespace GTutorial::Step1;

#ifdef _DEBUG
	spdlog::set_level(spdlog::level::debug);
#else
	spdlog::set_level(spdlog::level::info);
#endif

	LPCWSTR procName = L"gtutorial-x86_64.exe";
	DWORD processId = GetProcessIdByName(procName);

	if (processId == 0) {
		spdlog::critical(L"Can not find the process {}. End this program.", procName);
		return EXIT_FAILURE;
	}

	spdlog::info(L"Get process id of {} successfully.", procName);

	PBYTE baseAddr = NULL;
	DWORD baseSize = 0;
	if (GetProcessBaseAddr(processId, baseAddr, baseSize)) {
		spdlog::debug("Process Id   : {:d}", processId);
		spdlog::debug("Base Address : {:016x}", reinterpret_cast<DWORD64>(baseAddr));
		spdlog::debug("Base Size    : {:x}", baseSize);
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	if (hProcess == NULL) {
		CheckLastError();
		exit(EXIT_FAILURE);
	}

	spdlog::info("Shoot Counter : {:d}", ReadShootCounter(hProcess, baseAddr));

	PatchInfiniteAmmo(hProcess, baseAddr, baseSize);

	CloseHandle(hProcess);
	system("pause");

	return EXIT_SUCCESS;
}
