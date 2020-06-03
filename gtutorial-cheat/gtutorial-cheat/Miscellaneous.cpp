#include "Miscellaneous.h"
#include "spdlog_wrapper.h"

namespace {
    /* For integrity check code */
    BOOL gIsIntegrityCheckPatched = FALSE;
    LPVOID gIntegrityCheckCodeAddr = NULL;
    const BYTE gIntegrityCode[] = {
        0x0F, 0x94, 0x43, 0x70,     // set byte ptr [rbx+70]
        0x80, 0x7B, 0x70, 0x00      // cmp byte ptr [rbx+70], 00
    };
    constexpr SIZE_T gIntegrityCodeSz = sizeof(gIntegrityCode) / sizeof(gIntegrityCode[0]);
}

BOOL GTutorial::Misc::PatchIntegrityCheck(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize) {
    using namespace GTutorial::Helper;
    
    if (gIsIntegrityCheckPatched == TRUE) {
        spdlog::error("Integrity check patch is applied. You can not patch that code again.");
        return FALSE;
    }

    DWORD64 codeAddr = AOBScan(hProcess, baseAddr, baseSize, gIntegrityCode, gIntegrityCodeSz);
    spdlog::debug("AOBScan : {:016x}", codeAddr);

    if (codeAddr == NULL) {
        spdlog::error("Cannot find the victim code by AOBScan. Abort {} function", __FUNCTION__);
        return FALSE;
    }

    { // Patch instruction to selected point
        BYTE shellcode[] = {
            0xC6, 0x43, 0x70, 0x01,     // mov byte ptr [rbx+70], 1
            0x80, 0x7B, 0x70, 0x00      // cmp byte ptr [rbx+70], 00
        };
        constexpr SIZE_T shellcodeSz = sizeof(shellcode) / sizeof(shellcode[0]);
        static_assert(shellcodeSz == gIntegrityCodeSz, "shellcodeSz must be equal to gIntegrityCodeSz");

        if (WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(codeAddr), shellcode, gIntegrityCodeSz, NULL) == 0) {
            CheckLastError();
            return FALSE;
        }
    }
    
    gIntegrityCheckCodeAddr = reinterpret_cast<LPVOID>(codeAddr);
    gIsIntegrityCheckPatched = TRUE;

    return TRUE;
}

BOOL GTutorial::Misc::UnpatchIntegrityCheck(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize) {
    using namespace GTutorial::Helper;

    if (gIsIntegrityCheckPatched == FALSE) {
        spdlog::error("Integrity check patch is not applied");
        return FALSE;
    }

    if (gIntegrityCheckCodeAddr == NULL) {
        spdlog::error("We do not know where the integrity check patch is applied to");
        return FALSE;
    }

    if (WriteProcessMemory(hProcess, (LPVOID)gIntegrityCheckCodeAddr, gIntegrityCode, gIntegrityCodeSz, NULL) == 0) {
        CheckLastError();
        return FALSE;
    }

    gIsIntegrityCheckPatched = TRUE;
    gIntegrityCheckCodeAddr = NULL;

    return TRUE;
}