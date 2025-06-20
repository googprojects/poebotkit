#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

// Get process ID by name
DWORD GetProcessIdByName(const std::wstring& processName) {
    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

// Get base address of the module
uintptr_t GetModuleBaseAddress(DWORD pid, const std::wstring& moduleName) {
    MODULEENTRY32W modEntry = { 0 };
    modEntry.dwSize = sizeof(modEntry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    uintptr_t baseAddr = 0;
    if (Module32FirstW(snapshot, &modEntry)) {
        do {
            if (moduleName == modEntry.szModule) {
                baseAddr = reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &modEntry));
    }

    CloseHandle(snapshot);
    return baseAddr;
}

int main() {
    std::wstring procName = L"PathOfExile.exe";
    DWORD pid = GetProcessIdByName(procName);
    if (pid == 0) {
        std::wcerr << L"Could not find process: " << procName << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process.\n";
        return 1;
    }

    uintptr_t baseAddr = GetModuleBaseAddress(pid, procName);
    if (baseAddr == 0) {
        std::cerr << "Failed to get base address.\n";
        CloseHandle(hProcess);
        return 1;
    }

    uintptr_t targetAddr = baseAddr + 0x3F1454E;
    wchar_t buffer[128] = { 0 };
    std::wstring lastClean;

    std::wcout << L"Monitoring: 0x" << std::hex << targetAddr << std::endl;

    while (true) {
        if (ReadProcessMemory(hProcess, (LPCVOID)targetAddr, &buffer, sizeof(buffer) - sizeof(wchar_t), nullptr)) {
            buffer[127] = L'\0';  // Force terminate just in case

            // Make sure string stops at first null
            std::wstring raw(buffer);
            size_t pos = raw.find(L'\0');
            std::wstring clean = raw.substr(0, pos);

            // Remove any trailing padding (extra 0s in wide string)
            while (!clean.empty() && clean.back() == L'0') {
                clean.pop_back();
            }

            if (!clean.empty() && clean != lastClean) {
                std::wcout << L"Value changed: " << clean << std::endl;
                lastClean = clean;
            }
        }
        else {
            std::cerr << "Failed to read memory.\n";
            break;
        }

        Sleep(500);
    }

    CloseHandle(hProcess);
    return 0;
}
