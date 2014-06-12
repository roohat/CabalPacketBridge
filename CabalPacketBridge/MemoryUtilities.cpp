#include <Windows.h>
#include "MemoryUtilities.h"

#include <stdio.h>

#pragma pack(1)
struct hook_patch
{
	BYTE opcode;
	DWORD address;
};
#pragma pack()

BOOL ApplyHook(HookType type, DWORD dwAddress, const void* pTarget)
{
	DWORD oldProtect;
	hook_patch newMem = {
		(BYTE)type,
		(DWORD)pTarget - (dwAddress + sizeof(DWORD)+sizeof(BYTE))
	};

	VirtualProtect((LPVOID)dwAddress, sizeof(hook_patch), PAGE_EXECUTE_READWRITE, &oldProtect);
	BOOL success = WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, &newMem, sizeof(hook_patch), NULL);
	VirtualProtect((LPVOID)dwAddress, sizeof(hook_patch), oldProtect, &oldProtect);
	return success;
}

// Scans a memory page for keyword
// 0x7F is wildcard character
DWORD MemoryPageScan(const char* keyword, DWORD kSize, LPVOID page)
{
	MEMORY_BASIC_INFORMATION mbi;
	size_t s = VirtualQuery(page, &mbi, sizeof(MEMORY_BASIC_INFORMATION32));
	if (!s)
		return NULL;

	for (DWORD addr = (DWORD)mbi.BaseAddress; addr <= ((DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize); addr++)
	{
		for (DWORD index = 0; index < kSize; index++)
		{
			if (*(char*)(addr + index) == *(char*)(keyword + index) || *(char*)(keyword + index) == 0x7F)
			{
				if (index + 1 == kSize)
					return addr;
			}
			else
			{
				break;
			}
		}
	}
	return NULL;
}