#pragma once

#include "CheatingHelper.h"

namespace GTutorial::Step1 {

	DWORD InitializeShootCounterAddr(HANDLE hProcess, LPBYTE baseAddr);

	DWORD ReadShootCounter(HANDLE hProcess, LPBYTE baseAddr);

	BOOL WriteShootCounter(HANDLE hProcess, LPBYTE baseAddr, DWORD value);

	VOID PatchInfiniteAmmo(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize);
	
	BOOL UnpatchInfiniteAmmo(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize);

};