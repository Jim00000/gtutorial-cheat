#pragma once

#include "CheatingHelper.h"

namespace GTutorial::Misc {

    BOOL PatchIntegrityCheck(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize);

    BOOL UnpatchIntegrityCheck(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize);

}