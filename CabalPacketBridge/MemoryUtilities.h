#include <Windows.h>

enum HookType {
	CALL = 0xE8,
	JMP = 0xE9,
};

BOOL ApplyHook(HookType type, DWORD dwAddress, const void* pTarget);
DWORD MemoryPageScan(const char* keyword, DWORD kSize, LPVOID page);