#include <windows.h>
#include <string>

DWORD baseAddress;
int clientVersion;
typedef int __stdcall fps();
fps* printFps;
typedef void _DrawCreature(int surface, int x, int y, int size, int outfitId, int* outfitColors, int addons, int edgeRed, int edgeGreen, int edgeBlue, int clipX, int clipY, int clipWidth, int clipHeight);
_DrawCreature* DrawCreature;
FILE* pFile;
HMODULE origLibrary;

void HookCall(DWORD dwCallAddress, DWORD dwNewAddress, LPDWORD pOldAddress) {
	DWORD dwOldProtect, dwNewProtect, dwOldCall, dwNewCall;
	BYTE call[4];

	dwNewCall = dwNewAddress - dwCallAddress - 5;
	*(DWORD*)call = dwNewCall;

	VirtualProtect((LPVOID)(dwCallAddress + 1), 4, PAGE_EXECUTE_WRITECOPY, &dwOldProtect);

	if (pOldAddress) {
		memcpy(&dwOldCall, (LPVOID)(dwCallAddress + 1), 4);
		*pOldAddress = dwCallAddress + dwOldCall + 5;
	}

	dwCallAddress += 1;
	*(DWORD*)dwCallAddress = *(DWORD*)&call;
	VirtualProtect((LPVOID)(dwCallAddress), 5, dwOldProtect, &dwNewProtect);
}

DWORD HookAsmCall(DWORD dwAddress, DWORD dwFunction) {
	DWORD dwOldProtect, dwNewProtect, dwOldCall, dwNewCall;
	HANDLE proc = GetCurrentProcess();

	VirtualProtectEx(proc, (LPVOID)(dwAddress), 5, PAGE_READWRITE, &dwOldProtect);

	dwNewCall = dwFunction - dwAddress - 5;
	dwOldCall = *(uint32_t*)(dwAddress + 1);

	*(uint8_t*)(dwAddress) = 0xE8;
	*(uint32_t*)(dwAddress + 1) = dwNewCall;

	VirtualProtectEx(proc, (LPVOID)(dwAddress), 5, dwOldProtect, &dwNewProtect);

	return dwOldCall;
}

void myDrawItem(
	int surface,
	int x, int y,
	int sizer,
	int itemPointer, int edgeR, int edgeG, int edgeB,
	int clipX, int clipY, int clipW, int clipH,
	int textFont = 2, int textRed = 192, int textGreen = 192, int textBlue = 192, int textAlign = 2,
	int textForce = 0
) {
	int retvar;
	DWORD address = baseAddress + 0x149B60;

	__asm {
		push ebp
		push textForce
		push textAlign
		push textBlue
		push textGreen
		push textRed
		push textFont
		push clipH
		push clipW
		push clipY
		push clipX
		push edgeB
		push edgeG
		push edgeR
		push itemPointer
		push sizer
		push y
		mov edx, x
		mov ecx, surface
		call [address]
		add esp, 0x40
		mov retvar, eax
		leave
		retn
	}
}

void myDrawCreature(int x, int y, int size, int outfitId, int* outfitColors, int addons, int clipX, int clipY) {
	DrawCreature(1, x, y, size, outfitId, outfitColors, addons, 71, 71, 71, clipX, clipY, 138, 138);
}

void __fastcall HookedDrawItem(int surface, int x, int y, int size, int itemPointer, int edgeR, int edgeG, int edgeB, int clipX, int clipY, int clipW, int clipH, int arg12, int arg13, int arg14, int arg15, int arg16, int arg17) {
	fprintf(
		pFile,
		"HookedDrawItem - x: %d, y: %d, size: %d, itemPointer: %d, edgeR: %d, edgeG: %d, edgeB: %d, clipX: %d, clipY: %d, clipW: %d, clipH: %d\n",
		x, y, size, itemPointer, edgeR, edgeG, edgeB, clipX, clipY, clipW, clipH
	);
	fflush(pFile);
	myDrawItem(surface, x, y, size, itemPointer, edgeR, edgeG, edgeB, clipX, clipY, clipW, clipH);
}

int myPrintFps() {
	if (clientVersion == 860) {
		int outfitSize = 64;
		myDrawCreature(64, 94, outfitSize, 3, (int*)(baseAddress + 0x14), 0, 22, 52); // war wolf
		myDrawCreature(64, 74, outfitSize, 128, (int*)(baseAddress + 0x14), 0, 22, 32); // male citizen
	}
	else {
		//myDrawItem(1, 32, 32, 32, ???, 0, 0, 0, 32, 32, 32, 32);
	}

	return printFps();
}

extern "C" __declspec (dllexport) HRESULT WINAPI DirectDrawCreate(void* lpGUID, void* lplp, void* pUnkOuter) {
	FARPROC proc = GetProcAddress(origLibrary, "DirectDrawCreate");
	if (!proc)
		return E_INVALIDARG;

	return ((HRESULT(WINAPI*)(void*, void*, void*))(DWORD) (proc))(lpGUID, lplp, pUnkOuter);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
		return true;
	}

	char systemDirectory[MAX_PATH];
	GetSystemDirectory(systemDirectory, MAX_PATH);
	lstrcat(systemDirectory, "\\ddraw.dll");
	origLibrary = LoadLibrary(systemDirectory);

	baseAddress = (DWORD)GetModuleHandle(NULL);
	pFile = fopen("dll.log", "w");
	DWORD entrypoint = *(DWORD*)(baseAddress + 0x148);

	if (entrypoint == 0x1625EB) {
		clientVersion = 860;
		HookCall(baseAddress + 0x5A34A, (DWORD)&myPrintFps, (LPDWORD)&printFps);
		DrawCreature = (_DrawCreature*)(baseAddress + 0xB5E90);
	}
	else {
		clientVersion = 1098;
		HookCall(baseAddress + 0xA500F, (DWORD)&myPrintFps, (LPDWORD)&printFps);
		HookAsmCall(baseAddress + 0x826B2, (DWORD)&HookedDrawItem);
	}

	return true;
}
