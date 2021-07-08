# Draw item approach

Hello.

This repository shows how to hook for a DrawItem internal function to draw player's equipment items and hopefully will show how to draw any item where user want to.
Code can be compiled using Microsoft Visual Studio and will produce small `ddraw.dll` file.

## Code explanation

### 1. Load DLL without external tools and modifying original executable.

Executable originally calls many methods from many libraries and one of them is `DirectDrawCreate` from system `ddraw.dll` file. To make client load our code, we can name our dll as `ddraw.dll` and provide method it needs inside `APIENTRY DllMain` with
```c++
HMODULE origLibrary;

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

    // our code, like init() to main method

    return true;
}
```

### 2. Hooking into method responsile for printing FPS (even without ALT+F8 activated).

It's simple hook to memory region where function is called, provide own code and then execute original function which is done with

```c++
typedef int __stdcall fps();
fps* printFps;

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

int myPrintFps() {
	//our print code here

	return printFps();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
		return true;
	}

	baseAddress = (DWORD)GetModuleHandle(NULL);
	HookCall(baseAddress + 0xA500F, (DWORD)&myPrintFps, (LPDWORD)&printFps);

	return true;
}
```

`0xA500F` is the offset where client calls function originally.

### 3. DrawItem hook.

Hooking is similar to print fps function, but it's just passed our method which I've done with
```c++
FILE* pFile;

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

void __fastcall HookedDrawItem(int surface, int x, int y, int size, int itemPointer, int edgeR, int edgeG, int edgeB, int clipX, int clipY, int clipW, int clipH, int arg12, int arg13, int arg14, int arg15, int arg16, int arg17) {
	fprintf(
		pFile,
		"HookedDrawItem - x: %d, y: %d, size: %d, itemPointer: %d, edgeR: %d, edgeG: %d, edgeB: %d, clipX: %d, clipY: %d, clipW: %d, clipH: %d\n",
		x, y, size, itemPointer, edgeR, edgeG, edgeB, clipX, clipY, clipW, clipH
	);
	fflush(pFile);
	myDrawItem(surface, x - 10, y, size, itemPointer, edgeR, edgeG, edgeB, clipX, clipY, clipW, clipH);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
		return true;
	}

	baseAddress = (DWORD)GetModuleHandle(NULL);
	pFile = fopen("dll.log", "w");
	HookAsmCall(baseAddress + 0x826B2, (DWORD)&HookedDrawItem);

	return true;
}
```

`0x826B2` is the offset where equipment items are drawn and `0x149B60` is the offset where function reside. The main difference in `DrawItem` with https://github.com/ianobermiller/tibiaapi/blob/master/tibiaapi/InjectedDLL/Core.h#L52 is that in newer client `__fastcall` was needed (because of `surface` and `x` arguments placed inside registers). Also, in older clients item info is placed inside `int itemId, int itemData1, int itemData2` (where `itemData1` is item count) and in current those information are inside some structure placed in `itemPointer` where something else writes to it just before drawing.

`__asm` code is used, because I have troubles using C++ `typedef` code.

# Issue?

I can see my hook works, because of lines showing inside `dll.log` file:
```
HookedDrawItem - x: 1788, y: 156, size: 32, itemPointer: 24110004, edgeR: 0, edgeG: 0, edgeB: 0, clipX: 1788, clipY: 156, clipW: 32, clipH: 32
HookedDrawItem - x: 1825, y: 170, size: 32, itemPointer: 24110004, edgeR: 0, edgeG: 0, edgeB: 0, clipX: 1825, clipY: 170, clipW: 32, clipH: 32
HookedDrawItem - x: 1788, y: 193, size: 32, itemPointer: 24110004, edgeR: 0, edgeG: 0, edgeB: 0, clipX: 1788, clipY: 193, clipW: 32, clipH: 32
HookedDrawItem - x: 1751, y: 207, size: 32, itemPointer: 24110004, edgeR: 0, edgeG: 0, edgeB: 0, clipX: 1751, clipY: 207, clipW: 32, clipH: 32
HookedDrawItem - x: 1788, y: 230, size: 32, itemPointer: 24110004, edgeR: 0, edgeG: 0, edgeB: 0, clipX: 1788, clipY: 230, clipW: 32, clipH: 32
HookedDrawItem - x: 1788, y: 267, size: 32, itemPointer: 24110004, edgeR: 0, edgeG: 0, edgeB: 0, clipX: 1788, clipY: 267, clipW: 32, clipH: 32
HookedDrawItem - x: 1825, y: 244, size: 32, itemPointer: 24110004, edgeR: 0, edgeG: 0, edgeB: 0, clipX: 1825, clipY: 244, clipW: 32, clipH: 32
```

but I'm not able to create item structure (I guess it's itemID, itemCount, maybe some animation flag?) which I can write to `itemPointer` offset and use inside `myDrawItem(1, 32, 32, 32, ???, 0, 0, 0, 32, 32, 32, 32);` for example.
