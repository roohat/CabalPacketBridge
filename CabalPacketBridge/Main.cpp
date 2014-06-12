#include <Windows.h>
#include <stdio.h>
#include "dirent.h"
#include "MemoryUtilities.h"

// search patterns

const DWORD Encrypt_PatternOffset = 0;
const char Encrypt_Pattern[] = { 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x57, 0x8B, 0xF8, 0x74, 0x22, 0x56 };
const DWORD Decrypt_PatternOffset = 0;
const char Decrypt_Pattern[] = { 0x56, 0x8B, 0xF0, 0xC1, 0xF8, 0x02, 0xBA, 0x7F, 0x7F, 0x7F, 0x7F, 0x85, 0xC0 };
const DWORD InternalSend_PatternOffset = 0;
const char InternalSend_Pattern[] = { 0x56, 0x57, 0x8D, 0x71, 0x0C, 0x6A, 0x00, 0x8B, 0xC6 };


// linked list of mods
struct modDll {
	void* Initialize;
	void* SendHook;
	void* RecvHook;
	void* Terminate;
	struct modDll* next;
};

modDll* childDll = NULL;

////// Mod calls

typedef void(*ModInitializeFunc)(void*);
typedef void(*ModSendRecvHookFunc)(void*, void*, int);
typedef void(*ModTerminateFunc)();

void Initialize(void* sendhook)
{
	if (modDll* curDll = childDll)
	{
		do
		{
			((ModInitializeFunc)curDll->Initialize)(sendhook);
		} while (curDll = curDll->next);
	}
}

void SendHook(void* socket, void* packet, int len)
{
	if (modDll* curDll = childDll)
	{
		do
		{
			((ModSendRecvHookFunc)curDll->SendHook)(socket, packet, len);
		} while (curDll = curDll->next);
	}
}

void RecvHook(void* socket, void* packet, int len)
{
	if (modDll* curDll = childDll)
	{
		do
		{
			((ModSendRecvHookFunc)curDll->RecvHook)(socket, packet, len);
		} while (curDll = curDll->next);
	}
}

void Terminate()
{
	if (modDll* curDll = childDll)
	{
		do
		{
			((ModTerminateFunc)curDll->Terminate)();
		} while (curDll = curDll->next);
	}
}

////// Hooking code

DWORD Encrypt_OriginalPtr;
int __declspec(naked) __stdcall Encrypt_Original(void* socket, void* packet, int len)
{
	// calling the real encrypt is a bit weird because we must place socket into EAX. we can do that by messing around in ASM a bit :)
	__asm {
		POP EBX // EBX now holds call-return-addr
		POP EAX // EAX now holds socket
		PUSH EBX // place call-return-addr back on stack
		// replicate the first 7 bytes of the real function
		PUSH EBP
		MOV EBP, ESP
		CMP DWORD PTR SS : [EBP + 8], 0
		// jmp 7 bytes into the real function
		MOV EBX, Encrypt_OriginalPtr
		ADD EBX, 7
		JMP EBX
	}
}

int __stdcall Encrypt_Hook(void* packet, int len)
{
	void* socket;
	__asm {
		MOV socket, EAX // for some reason, EAX is _always_ the socket
	}

	SendHook(socket, packet, len);
	Encrypt_Original(socket, packet, len);
}

DWORD InternalSend_OriginalPtr; // pointer to the game's internal send func
void InjectSend(void* socket, void* packet, int len)
{
	Encrypt_Original(socket, packet, len);
	((void(__fastcall *)(void*))InternalSend_OriginalPtr)(socket);
}

DWORD Decrypt_OriginalPtr;
int __declspec(naked) __stdcall Decrypt_Original(void* packet, DWORD size, void* decryptionInfo)
{
	__asm
	{
		POP ESI // esp holds return address
		POP ECX // ecx holds pointer to packet
		POP EAX // eax holds size
		PUSH ESI // put return addr back

		// replicate first 6 bytes of the real function
		PUSH ESI
		MOV ESI, EAX
		SAR EAX, 2

		// jmp 6 bytes into real function
		MOV EBX, Decrypt_OriginalPtr
		ADD EBX, 6
		JMP EBX
	}
}

int __stdcall Decrypt_Hook(void* decryptionInfo)
{
	DWORD len;
	void* packet;
	__asm {
		MOV len, EAX // eax is always length
		MOV packet, ECX // ecx is always buffer pointer
	}

	int ret = Decrypt_Original(packet, len, decryptionInfo);
	RecvHook(0, packet, len);
	return ret;
}

////// Mod loading code

modDll* AddModNode(void* initialize, void* sendhook, void* recvhook, void* terminate)
{
	modDll* curDll;
	if (childDll == NULL)
	{
		curDll = childDll = (modDll*)malloc(sizeof(modDll));
	}
	else
	{
		curDll = childDll;
		while (curDll->next != NULL)
		{
			curDll = curDll->next;
		}

		curDll = curDll->next = (modDll*)malloc(sizeof(modDll));
	}

	curDll->Initialize = initialize;
	curDll->SendHook = sendhook;
	curDll->RecvHook = recvhook;
	curDll->Terminate = terminate;
	curDll->next = NULL;

	return curDll;
}

void LoadMods()
{
	DIR* modDirectory;
	struct dirent* ent;

	// buffer for dll path
	char bufPath[MAX_PATH] = ".\\mod\\";


	if ((modDirectory = opendir(".\\mod\\")) != NULL)
	{
		while ((ent = readdir(modDirectory)) != NULL)
		{
			// if the file ends with .dll, we load it
			if ((ent->d_type != DT_DIR) && (strcmp(ent->d_name + ent->d_namlen - 4, ".dll") == 0))
			{
				printf("CPB : Loading %s", ent->d_name);
				strcpy(bufPath + 6, ent->d_name);
				if (HMODULE loadedLib = LoadLibraryA(bufPath))
				{
					printf(" ... ok!");
					AddModNode(
						GetProcAddress(loadedLib, "Initialize"),
						GetProcAddress(loadedLib, "SendHook"),
						GetProcAddress(loadedLib, "RecvHook"),
						GetProcAddress(loadedLib, "Terminate"));
				}
				printf("\n");
			}
		}
	}

	Initialize(InjectSend);
}

////// Hook setup

void SetupHooks()
{
	// get addresses
	Decrypt_OriginalPtr = MemoryPageScan(Decrypt_Pattern, sizeof(Decrypt_Pattern), (LPVOID)0x401000) + Decrypt_PatternOffset;
	Encrypt_OriginalPtr = MemoryPageScan(Encrypt_Pattern, sizeof(Encrypt_Pattern), (LPVOID)0x401000) + Encrypt_PatternOffset;
	InternalSend_OriginalPtr = MemoryPageScan(InternalSend_Pattern, sizeof(InternalSend_Pattern), (LPVOID)0x401000) + InternalSend_PatternOffset;

	// hook functions
	ApplyHook(JMP, Decrypt_OriginalPtr, Decrypt_Hook);
	ApplyHook(JMP, Encrypt_OriginalPtr, Encrypt_Hook);
}

////// Entry Point

DWORD WINAPI StartCabalPacketBridge(void* params)
{
	SetupHooks();
	LoadMods();
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, StartCabalPacketBridge, 0, 0, 0);
		break;
	case DLL_PROCESS_DETACH:
		Terminate();
		break;
	}

	return TRUE;
}