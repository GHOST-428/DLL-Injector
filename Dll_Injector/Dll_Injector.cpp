#include <windows.h>
#include <string>
#include <TlHelp32.h>
#include <iostream>

int main() {
    std::string dllPath = "Cheat.dll";
    std::string processName = "Secret Neighbour.exe";

    // Get the process ID of the target process
    DWORD processID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (std::string(pe32.szExeFile) == processName) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    if (processID == 0) {
        std::cout << "Could not find the process: " << processName << std::endl;
        return 1;
    }

    // Get the full path of the DLL
    char fullDllPath[MAX_PATH];
    GetFullPathName(dllPath.c_str(), MAX_PATH, fullDllPath, NULL);

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cout << "Could not open the process." << std::endl;
        return 1;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, strlen(fullDllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddr == NULL) {
        std::cout << "Could not allocate memory in the process." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, dllPathAddr, fullDllPath, strlen(fullDllPath) + 1, NULL)) {
        std::cout << "Could not write to the process memory." << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Get the address of the LoadLibrary function
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cout << "Could not get the LoadLibrary address." << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, dllPathAddr, 0, NULL);
    if (hThread == NULL) {
        std::cout << "Could not create a remote thread." << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Free the allocated memory and close handles
    VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully." << std::endl;

    return 0;
}