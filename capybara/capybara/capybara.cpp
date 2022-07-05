#define WIN32_LEAN_AND_MEAN
#define FMT_HEADER_ONLY

#include <windows.h> 
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <stdio.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <fmt/format.h>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

HANDLE h_console = GetStdHandle(STD_OUTPUT_HANDLE);

void print_error(std::string text);
void print_success(std::string text);
void print_info(std::string text);
void draw_header();
bool is_proc_running(const wchar_t* proc_name);
int get_proc_id(const wchar_t* proc_name);
void inject_into_proc(std::string dll_name, int& process_id);

int main()
{
    SetConsoleTitle(L"Capybara Injector - by MoppyX");
    std::vector<std::string> dll_options;
    std::string selected_dll;

    draw_header();
    print_success("[+] Suche nach Executor DLL...");
    for (const auto& entry : fs::directory_iterator(".")) {
        if (entry.path().extension().string() == ".dll") dll_options.push_back(entry.path().string());
    }
    if (dll_options.size() > 0) {
        if (dll_options.size() == 1) {
            print_success("[+] MoppyX.dll gefunden!");
            selected_dll = fs::absolute(dll_options[0]).string();
        }
        else {
            print_info(fmt::format("[!] Finde {} DLLs:", dll_options.size()));
            for (auto i = 0; i < dll_options.size(); ++i) {
                std::cout << i + 1 << ") " << dll_options[i] << std::endl;
            }
            std::cout << fmt::format("Welche DLL soll Injected werden?", dll_options.size()) << std::endl << "> ";
            int selection;
            std::cin >> selection;
            while (std::cin.fail() || !(selection > 0 && selection <= dll_options.size())) {
                print_error("[-] Falscher Input! Bitte versuche es erneut.");
                std::cout << "> ";
                std::cin.clear();
                std::cin.ignore(256, '\n');
                std::cin >> selection;
            }
            selected_dll = dll_options[selection - 1];
        }

        print_info("[!] Warte auf FiveM_GTAProcess...");
        while (!is_proc_running(L"FiveM_b2372_GTAProcess.exe")) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        print_success("[+] FiveM_GTAProcess.exe gefunden. Warte ein paar Sekunden...");
        std::this_thread::sleep_for(std::chrono::milliseconds(10000));

        print_success("[+] Probiere in FiveM_GTAProcess zu Injecten...");
        int proc_id = get_proc_id(L"FiveM_b2372_GTAProcess.exe");
        if (!proc_id == 0) {
            inject_into_proc(selected_dll, proc_id);
        }
        else {
            print_error("[-] Irgendetwas lief schief mit deiner ProcessId.");
        }
    }
    else {
        print_error("[-] Keine DLLs in diesem Path gefunden!");
    }
    std::cin.get();
    return 0;
}

void print_error(std::string text) {
    SetConsoleTextAttribute(h_console, 12);
    std::cout << text << std::endl;
    SetConsoleTextAttribute(h_console, 15);
}
void print_success(std::string text) {
    SetConsoleTextAttribute(h_console, 11);
    std::cout << text << std::endl;
    SetConsoleTextAttribute(h_console, 15);
}
void print_info(std::string text) {
    SetConsoleTextAttribute(h_console, 10);
    std::cout << text << std::endl;
    SetConsoleTextAttribute(h_console, 15);
}
void draw_header() {
    SetConsoleTextAttribute(h_console, 15);
    std::cout << R"(
   _____                  _
  / ____|                | |
 | |     __ _ _ __  _   _| |__   __ _ _ __ __ _ 
 | |    / _` | '_ \| | | | '_ \ / _` | '__/ _` |
 | |___| (_| | |_) | |_| | |_) | (_| | | | (_| |
  \_____\__,_| .__/ \__, |_.__/ \__,_|_|  \__,_|
             | |     __/ |                     
             |_|    |___/                        
        )" << "\n";
    print_success("             Capybara Injector V1");
    std::cout << "-----------------------------------------------" << std::endl;
}

bool is_proc_running(const wchar_t* proc_name) {
    bool is_running = false;
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(proc_snap, &process_entry))
        while (Process32Next(proc_snap, &process_entry))
            if (!_wcsicmp(process_entry.szExeFile, proc_name))
                is_running = true;

    CloseHandle(proc_snap);
    return is_running;
}

int get_proc_id(const wchar_t* proc_name) {
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(proc_snap, &process_entry))
        while (Process32Next(proc_snap, &process_entry))
            if (!_wcsicmp(process_entry.szExeFile, proc_name)) {
                CloseHandle(proc_snap);
                return process_entry.th32ProcessID;
            }

    CloseHandle(proc_snap);
    return 0;
}

void inject_into_proc(std::string dll_name, int& process_id) {
    dll_name = fs::absolute(dll_name).string();
    long dll_length = static_cast<long>(dll_name.length() + 1);
    HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
    if (proc_handle == NULL) {
        print_error("[-] Ich kann das Programm nicht öffnen.");
        return;
    }
    LPVOID virt_alloc = VirtualAllocEx(proc_handle, NULL, dll_length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (virt_alloc == NULL) {
        print_error("[-] Speicherzuweisung innerhalb des Prozesses fehlgeschlagen.");
        return;
    }
    int write_dll_to_mem = WriteProcessMemory(proc_handle, virt_alloc, dll_name.c_str(), dll_length, 0);
    if (write_dll_to_mem == 0) {
        print_error("[-] Fehler beim Schreiben der DLL in den Speicher.");
        return;
    }
    DWORD thread_id;
    LPTHREAD_START_ROUTINE load_lib = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(LoadLibraryA("kernel32"), "LoadLibraryA"));
    HANDLE new_thread = CreateRemoteThread(proc_handle, NULL, 0, load_lib, virt_alloc, 0, &thread_id);
    if (new_thread == NULL) {
        print_error("[-] Fehler beim Erstellen des laufenden Threads.");
        return;
    }
    if (proc_handle != NULL && virt_alloc != NULL && write_dll_to_mem != ERROR_INVALID_HANDLE && new_thread != NULL) {
        print_success("[+] MoppyX.dll wurde erfolgreich Injected!");
    }
    return;
}