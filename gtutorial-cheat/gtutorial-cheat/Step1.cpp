#include <iostream>
#include "Step1.h"

namespace {
    DWORD gShootCounterAddr = 0;

    /* For infinite ammo patch */
    BOOL gIsInfiniteAmmoPatched = FALSE;
    LPVOID gInfiniteAmmoNewMemBlock = NULL;
    LPVOID gInfiniteAmmoPatchCode = NULL;
    const BYTE gVictim[] = {
        0x83, 0x43, 0x6C, 0x01,         // add dword ptr [rbx+6C],01
        0x48, 0x89, 0x73, 0x70,         // mov [rbx+70],rsi
        0x48, 0x63, 0x43, 0x6C,         // movsxd rax,dword ptr [rbx+6C]
        0xBA, 0x05, 0x00, 0x00, 0x00    // mov edx,00000005
    };
    constexpr SIZE_T gVictimSz = sizeof(gVictim) / sizeof(gVictim[0]);

}

DWORD GTutorial::Step1::InitializeShootCounterAddr(HANDLE hProcess, LPBYTE baseAddr) {
    using namespace GTutorial::Helper;
    DWORD remoteAddr = 0;
    remoteAddr = ReadMemory(hProcess, baseAddr + 0x3CCD20);
    remoteAddr = ReadMemory(hProcess, remoteAddr + 0x7C0);
    return remoteAddr + 0x6C;
}

DWORD GTutorial::Step1::ReadShootCounter(HANDLE hProcess, LPBYTE baseAddr) {
    using namespace GTutorial::Helper;

    if (gShootCounterAddr == 0) {
        gShootCounterAddr = InitializeShootCounterAddr(hProcess, baseAddr);
    }

    return ReadMemory(hProcess, gShootCounterAddr);
}

BOOL GTutorial::Step1::WriteShootCounter(HANDLE hProcess, LPBYTE baseAddr, DWORD value) {
    using namespace GTutorial::Helper;

    if (gShootCounterAddr == 0) {
        gShootCounterAddr = InitializeShootCounterAddr(hProcess, baseAddr);
    }

    return WriteMemory(hProcess, gShootCounterAddr, value);
}

VOID GTutorial::Step1::PatchInfiniteAmmo(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize) {
    using namespace GTutorial::Helper;

    if (gIsInfiniteAmmoPatched == TRUE) {
        std::cerr << "InfiniteAmmo Cheat is activated. You can patch the code again." << std::endl;
        return;
    }

    DWORD64 victimAddr = AOBScan(hProcess, baseAddr, baseSize, gVictim, gVictimSz);
    std::cout << "AOBScan : " << (void*)victimAddr << std::endl;

    if (victimAddr == NULL) {
        std::cerr << "Cannot find the victim code by AOBScan. Terminate PatchInfiniteAmmo(...) function" << std::endl;
        return;
    }

    LPVOID rNewMemBlock = NewMemoryBlock(hProcess, 4096);
    std::cout << "remote new memory block : " << (void*)rNewMemBlock << std::endl;

    { // Patch instruction to selected point
        BYTE shellcode[] = {
            0x49, 0xBF,                                     // movabs r15, <target address>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x41, 0xFF, 0xE7,                               // jmp r15
            0x90, 0x90, 0x90, 0x90                          // 4 nops
        };
        constexpr SIZE_T shellcodeSz = sizeof(shellcode) / sizeof(shellcode[0]);
        static_assert(shellcodeSz == gVictimSz, "shellcodeSz must be equal to gVictimSz");

        DWORD64* pImm = (DWORD64*)&shellcode[2];
        // Write new memory block address to <target address> of movabs instruction
        *pImm = (DWORD64)rNewMemBlock;

        if (WriteProcessMemory(hProcess, (LPVOID)victimAddr, shellcode, gVictimSz, NULL) == 0) {
            CheckLastError();
            FreeMemoryBlock(hProcess, rNewMemBlock);
            return;
        }
    }

    { // Write data to memory block
        BYTE shellcode[] = {
            // We disable "add dword ptr [rbx+6C],01"
            0x48, 0x89, 0x73, 0x70,                         // mov [rbx+70],rsi
            0x48, 0x63, 0x43, 0x6C,                         // movsxd rax,dword ptr [rbx+6C]
            0xBA, 0x05, 0x00, 0x00, 0x00,                   // mov edx,00000005
            0x49, 0xBF,                                     // movabs r15, <target address>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x41, 0xFF, 0xE7                                // jmp r15
        };
        constexpr SIZE_T shellcodeSz = sizeof(shellcode) / sizeof(shellcode[0]);

        DWORD64* pImm = (DWORD64*)&shellcode[15];
        // Write return address (back to vicitm code) 
        // to <target address> of movabs instruction
        *pImm = (victimAddr + gVictimSz);


        if (WriteProcessMemory(hProcess, rNewMemBlock, shellcode, shellcodeSz, NULL) == 0) {
            CheckLastError();
            FreeMemoryBlock(hProcess, rNewMemBlock);
            return;
        }
    }

    // The patch is successful
    gIsInfiniteAmmoPatched = TRUE;
    gInfiniteAmmoNewMemBlock = rNewMemBlock;
    gInfiniteAmmoPatchCode = reinterpret_cast<decltype(gInfiniteAmmoPatchCode)>(victimAddr);
}

BOOL GTutorial::Step1::UnpatchInfiniteAmmo(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize) {
    using namespace GTutorial::Helper;

    if (gIsInfiniteAmmoPatched == FALSE) {
        std::cerr << "Infinite ammo patch is not applied" << std::endl;
        return FALSE;
    }

    if (gInfiniteAmmoPatchCode == NULL) {
        std::cerr << "We do not know where the \"infinite ammo\" patch is applied to" << std::endl;
        return FALSE;
    }

    if (gInfiniteAmmoNewMemBlock == NULL) {
        std::cerr << "We do not know where is the memory block of \"infinite ammo\"" << std::endl;
        return FALSE;
    }

    if (WriteProcessMemory(hProcess, (LPVOID)gInfiniteAmmoPatchCode, gVictim, gVictimSz, NULL) == 0) {
        CheckLastError();
        return FALSE;
    }
    
    gIsInfiniteAmmoPatched = FALSE;
    gInfiniteAmmoPatchCode = NULL;

    if (FreeMemoryBlock(hProcess, gInfiniteAmmoNewMemBlock) == FALSE) {
        return FALSE;
    }

    gInfiniteAmmoNewMemBlock = NULL;
    return TRUE;
}