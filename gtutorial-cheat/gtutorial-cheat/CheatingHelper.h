#pragma once

#include <Windows.h>
#include <type_traits>
#include <stdio.h>

namespace GTutorial::Helper {

	VOID CheckLastError();

	BOOL GetProcessBaseAddr(DWORD pid, LPBYTE& baseAddr, DWORD& baseSize);

	DWORD GetProcessIdByName(LPCWSTR procName);

	DWORD64 AOBScan(HANDLE hProcess, LPBYTE baseAddr, DWORD baseSize, LPCBYTE victim, SIZE_T victimSz);

	LPVOID NewMemoryBlock(HANDLE hProcess, SIZE_T size);

	BOOL FreeMemoryBlock(HANDLE hProcess, LPVOID lpAddress);

	template<
		typename DataType = DWORD,
		typename = std::enable_if_t<std::is_scalar_v<DataType>&& std::is_fundamental_v<DataType>>
	>
	DataType ReadMemory(HANDLE hProcess, LPCVOID baseAddr)
	{
		BYTE buffer[BUFSIZ];
		ZeroMemory(buffer, BUFSIZ);

		DataType result = NULL;

		if (ReadProcessMemory(hProcess, baseAddr, buffer, sizeof(DataType), NULL) == 0) {
			CheckLastError();
		}

		const auto rAddr = reinterpret_cast<std::add_pointer_t<DataType>>(&buffer);

		return *rAddr;
	}

	template<
		typename DataType = DWORD, typename AddrType,
		typename = std::enable_if_t<std::is_scalar_v<DataType> && std::is_fundamental_v<DataType>>
	>
	DataType ReadMemory(HANDLE hProcess, AddrType baseAddr)
	{
		return ReadMemory<DataType>(hProcess, reinterpret_cast<std::enable_if_t<sizeof(LPCVOID) >= sizeof(AddrType), LPCVOID>>(baseAddr));
	}

	template<typename DataType, 
		typename = std::enable_if_t<std::is_scalar_v<DataType> && std::is_fundamental_v<DataType>>
	>
	BOOL WriteMemory(HANDLE hProcess, LPVOID baseAddr, DataType value)
	{
		BYTE buffer[BUFSIZ];
		ZeroMemory(buffer, BUFSIZ);

		*reinterpret_cast<std::add_pointer_t<DataType>>(buffer) = value;

		if (WriteProcessMemory(hProcess, baseAddr, buffer, sizeof(DataType), NULL) == 0) {
			CheckLastError();
			return FALSE;
		}

		return TRUE;
	}

    template<
        typename DataType, typename AddrType,
        typename = std::enable_if_t<std::is_scalar_v<DataType> && std::is_fundamental_v<DataType>>
	>
    BOOL WriteMemory(HANDLE hProcess, AddrType baseAddr, DataType value)
    {
        return WriteMemory<DataType>(hProcess, reinterpret_cast<std::enable_if_t<sizeof(LPVOID) >= sizeof(AddrType), LPVOID>>(baseAddr), value);
    }

}
