#include <beacon.h>
#include <tlhelp32.h>
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <exception>

// procwatch: sample async BOF-PE.
// Polls the process list and reports processes that started or exited since
// the previous poll. It runs until the C2 signals the stop job event.
// BeaconWakeup is called only when something changed, so the implant stays
// asleep while nothing happens.

using ProcessMap = std::unordered_map<DWORD, std::string>;

static std::string to_utf8(const wchar_t* str) {
    int size = WideCharToMultiByte(CP_UTF8, 0, str, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1)
        return {};
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, str, -1, result.data(), size, nullptr, nullptr);
    return result;
}

static ProcessMap snapshot_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateToolhelp32Snapshot failed: " + std::to_string(GetLastError()));

    ProcessMap processes;
    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            processes[entry.th32ProcessID] = to_utf8(entry.szExeFile);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processes;
}

struct ProcessDiff {
    std::string report;
    unsigned started = 0;
    unsigned exited = 0;
};

// A PID that was reused by a different image counts as one exit and one start
static ProcessDiff diff_processes(const ProcessMap& before, const ProcessMap& after) {
    ProcessDiff diff;

    for (const auto& [pid, name] : after) {
        auto it = before.find(pid);
        if (it == before.end() || it->second != name) {
            diff.report += "[+] " + std::to_string(pid) + "\t" + name + "\n";
            ++diff.started;
        }
    }

    for (const auto& [pid, name] : before) {
        auto it = after.find(pid);
        if (it == after.end() || it->second != name) {
            diff.report += "[-] " + std::to_string(pid) + "\t" + name + "\n";
            ++diff.exited;
        }
    }

    return diff;
}

// A C2 without the async API can leave the BeaconGetStopJobEvent import
// unresolved (NULL). GCC assumes a function address is never NULL and drops a
// plain `BeaconGetStopJobEvent != nullptr` check, so read it through a volatile.
static HANDLE get_stop_job_event() {
    decltype(&BeaconGetStopJobEvent) volatile fn = &BeaconGetStopJobEvent;
    return fn != nullptr ? fn() : nullptr;
}

static void watch(DWORD interval, HANDLE stop_event) {
    ProcessMap current = snapshot_processes();
    unsigned started = 0, exited = 0, ticks = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] procwatch started: %u processes, polling every %lu ms\n",
        (unsigned)current.size(), interval);

    // WAIT_TIMEOUT means the interval elapsed with no stop request
    while (WaitForSingleObject(stop_event, interval) == WAIT_TIMEOUT) {
        ProcessMap next = snapshot_processes();
        ProcessDiff diff = diff_processes(current, next);

        if (!diff.report.empty()) {
            started += diff.started;
            exited += diff.exited;
            BeaconOutput(CALLBACK_OUTPUT, diff.report.data(), (int)diff.report.length());
            BeaconWakeup();
        }

        current = std::move(next);
        ++ticks;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] procwatch stopped after %u polls: %u started, %u exited\n",
        ticks, started, exited);
}

extern "C" __declspec(dllexport) void go(const char* data, int len) {

    BEACON_INIT;

    try {
        datap args = { 0 };
        BeaconDataParse(&args, (char*)data, len);
        int interval = BeaconDataInt(&args);
        if (interval <= 0)
            interval = 2000;

        // The C2 owns this handle, do not close it
        HANDLE stop_event = get_stop_job_event();
        if (stop_event == nullptr) {
            BeaconPrintf(CALLBACK_ERROR, "[!] procwatch must run as an async BOF (no stop job event from the C2)\n");
            return;
        }

        watch((DWORD)interval, stop_event);
    }
    catch (const std::exception& ex) {
        BeaconPrintf(CALLBACK_ERROR, "[!] procwatch: %s\n", ex.what());
    }
}

BEACON_MAIN("i", go)
