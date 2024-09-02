#include <chrono>
#include <iostream>
#include <thread>
#include <Windows.h>

int main() {
    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInformation;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFOA));

    bool success = CreateProcessA(R"(./Velocity.exe)", nullptr, nullptr, nullptr, 0, CREATE_SUSPENDED, nullptr, nullptr, &startupInfo, &processInformation);

    if (success == FALSE) {
        std::cout << "[-] Error creating Velocity process" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] Velocity process created" << std::endl;

    const auto dllPath = R"(./patcher.dll)";
    const auto dllPathAddr = VirtualAllocEx(processInformation.hProcess, nullptr, strlen(dllPath)+1, MEM_COMMIT, PAGE_READWRITE);

    if (dllPathAddr == nullptr) {
        std::cout << "[-] Error allocating memory" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return EXIT_FAILURE;
    }

    success = WriteProcessMemory(processInformation.hProcess, dllPathAddr, dllPath, strlen(dllPath)+1, nullptr);

    if (success == FALSE) {
        std::cout << "[-] Error writing dll path" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return EXIT_FAILURE;
    }

    auto loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    auto handle = CreateRemoteThread(processInformation.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr), dllPathAddr, 0, nullptr);

    DWORD ret = 0;
    WaitForSingleObject(handle, INFINITE);
    GetExitCodeThread(handle, &ret);

    if (handle == nullptr && ret == 0) {
        std::cout << "[-] Error creating remote thread" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return EXIT_FAILURE;
    }

    std::cout << "[+] LoadLibrary executed (0x" << std::hex << ret << ")" << std::endl;
    ResumeThread(processInformation.hThread);
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return EXIT_SUCCESS;
}
