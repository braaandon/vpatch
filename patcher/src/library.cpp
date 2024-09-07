#include <cstdio>
#include <iostream>
#include <Windows.h>

#include <MinHook.h>

uintptr_t moduleBase = 0x0;

typedef void(*empty)(void* api);
typedef void(*one_arg)(void* api, int64_t arg);

empty init_orig;
one_arg login_orig;
one_arg log_msg_orig;

void set_response(void*) {
    *reinterpret_cast<bool*>(moduleBase + 0xF3130) = true; // set response to successful
}

void one_arg_fn(void*, int64_t) {}

void entry() {
    AllocConsole();
    freopen("CON","w",stdout);
    std::cout << "[+] Patching...\n";

    if(MH_Initialize() != MH_OK) {
        std::cout << "[-] Failed to initialize MinHook\n";
        return;
    }

    std::cout << "[+] Initialized MinHook\n";

    moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA("Velocity.exe"));
    MH_CreateHook(reinterpret_cast<LPVOID>(moduleBase + 0x6A480), set_response, reinterpret_cast<void**>(&init_orig));
    MH_CreateHook(reinterpret_cast<LPVOID>(moduleBase + 0x6C2D0), one_arg_fn, reinterpret_cast<void**>(&login_orig));
    MH_CreateHook(reinterpret_cast<LPVOID>(moduleBase + 0x6D790), one_arg_fn, reinterpret_cast<void**>(&log_msg_orig));

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        std::cout << "[-] Failed to enable hooks\n";
    } else {
        std::cout << "[+] Enabled hooks\n";
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        entry();
    }

    return TRUE;
}
