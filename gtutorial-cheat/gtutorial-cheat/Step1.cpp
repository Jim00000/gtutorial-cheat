#include <iostream>
#include "Step1.h"

namespace {
    DWORD globShootCounterAddr = 0;

    /* For infinite ammo patch */
    BOOL globIsInfiniteAmmoPatched = FALSE;
    LPVOID globInfiniteAmmoNewMemBlock = NULL;
    LPVOID globInfiniteAmmoPatchCode = NULL;
    const BYTE victim[] = {
        0x83, 0x43, 0x6C, 0x01,			// add dword ptr [rbx+6C],01
        0x48, 0x89, 0x73, 0x70,			// mov [rbx+70],rsi
        0x48, 0x63, 0x43, 0x6C,			// movsxd rax,dword ptr [rbx+6C]
        0xBA, 0x05, 0x00, 0x00, 0x00    // mov edx,00000005
    };
    constexpr SIZE_T victimSz = 17;

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

    if (globShootCounterAddr == 0) {
        globShootCounterAddr = InitializeShootCounterAddr(hProcess, baseAddr);
    }

    return ReadMemory(hProcess, globShootCounterAddr);
}

BOOL GTutorial::Step1::WriteShootCounter(HANDLE hProcess, LPBYTE baseAddr, DWORD value) {
    using namespace GTutorial::Helper;

    if (globShootCounterAddr == 0) {
        globShootCounterAddr = InitializeShootCounterAddr(hProcess, baseAddr);
    }

    return WriteMemory(hProcess, globShootCounterAddr, value);
}

VOID GTutorial::Step1::PatchInfiniteAmmo(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize) {
    using namespace GTutorial::Helper;

    if (globIsInfiniteAmmoPatched == TRUE) {
        std::cerr << "InfiniteAmmo Cheat is activated. You can patch the code again." << std::endl;
        return;
    }

    DWORD64 victimAddr = AOBScan(hProcess, baseAddr, baseSize, victim, victimSz);
    std::cout << "AOBScan : " << (void*)victimAddr << std::endl;

    if (victimAddr == NULL) {
        std::cerr << "Cannot find the victim code by AOBScan. Terminate PatchInfiniteAmmo(...) function" << std::endl;
        return;
    }

    LPVOID rNewMemBlock = NewMemoryBlock(hProcess, 4096);
    std::cout << "remote new memory block : " << (void*)rNewMemBlock << std::endl;

    { // Patch instruction to selected point
        BYTE shellcode[] = {
            0x49, 0xBF,										// movabs r15, <target address>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x41, 0xFF, 0xE7,								// jmp r15
            0x90, 0x90, 0x90, 0x90							// 4 nops
        };

        DWORD64* pImm = (DWORD64*)&shellcode[2];
        // Write new memory block address to <target address> of movabs instruction
        *pImm = (DWORD64)rNewMemBlock;

        if (WriteProcessMemory(hProcess, (LPVOID)victimAddr, shellcode, victimSz, NULL) == 0) {
            CheckLastError();
            FreeMemoryBlock(hProcess, rNewMemBlock);
            return;
        }
    }

    { // Write data to memory block
        BYTE shellcode[] = {
            // We disable "add dword ptr [rbx+6C],01"
            0x48, 0x89, 0x73, 0x70,							// mov [rbx+70],rsi
            0x48, 0x63, 0x43, 0x6C,							// movsxd rax,dword ptr [rbx+6C]
            0xBA, 0x05, 0x00, 0x00, 0x00,					// mov edx,00000005
            0x49, 0xBF,										// movabs r15, <target address>
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x41, 0xFF, 0xE7								// jmp r15
        };

        DWORD64* pImm = (DWORD64*)&shellcode[15];
        // Write return address (back to vicitm code) 
        // to <target address> of movabs instruction
        *pImm = (victimAddr + victimSz);


        if (WriteProcessMemory(hProcess, rNewMemBlock, shellcode, 26, NULL) == 0) {
            CheckLastError();
            FreeMemoryBlock(hProcess, rNewMemBlock);
            return;
        }
    }

    // The patch is successful
    globIsInfiniteAmmoPatched = TRUE;
    globInfiniteAmmoNewMemBlock = rNewMemBlock;
    globInfiniteAmmoPatchCode = reinterpret_cast<decltype(globInfiniteAmmoPatchCode)>(victimAddr);
}

BOOL GTutorial::Step1::UnpatchInfiniteAmmo(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize) {
    using namespace GTutorial::Helper;

    if (globIsInfiniteAmmoPatched == FALSE) {
        std::cerr << "Infinite ammo patch is not applied" << std::endl;
        return FALSE;
    }

    if (globInfiniteAmmoPatchCode == NULL) {
        std::cerr << "We do not know where the \"infinite ammo\" patch is applied to" << std::endl;
        return FALSE;
    }

    if (globInfiniteAmmoNewMemBlock == NULL) {
        std::cerr << "We do not know where is the memory block of \"infinite ammo\"" << std::endl;
        return FALSE;
    }

    if (WriteProcessMemory(hProcess, (LPVOID)globInfiniteAmmoPatchCode, victim, victimSz, NULL) == 0) {
        CheckLastError();
        return FALSE;
    }
    
    globIsInfiniteAmmoPatched = FALSE;
    globInfiniteAmmoPatchCode = NULL;

    if (FreeMemoryBlock(hProcess, globInfiniteAmmoNewMemBlock) == FALSE) {
        return FALSE;
    }

    globInfiniteAmmoNewMemBlock = NULL;
    return TRUE;
}