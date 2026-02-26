#include "pch.h"
#include "ProcessMonitor.hpp"

#include <vector>
#include <set>
#include <string>
#include <algorithm>

#include <psapi.h>

namespace
{
    const uint32_t PROCESS_QUERY_RIGHTS = PROCESS_QUERY_LIMITED_INFORMATION;
    const uint32_t MAX_PATH_SIZE = 4096;
    const uint32_t MONITOR_INTERVAL_MS = 500;

    std::set<uint32_t> GetProcessSet()
    {
        std::set<uint32_t> processSet;
        std::vector<DWORD> pids(4096);
        DWORD bytesReturned = 0;

        if (EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &bytesReturned))
        {
            DWORD processCount = bytesReturned / sizeof(DWORD);
            for (DWORD i = 0; i < processCount; ++i)
            {
                processSet.insert(pids[i]);
            }
        }

        return processSet;
    }

    bool GetProcessPathInternal(uint32_t pid, std::wstring& path)
    {
        path.clear();

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_RIGHTS, FALSE, pid);
        if (hProcess == nullptr)
        {
            return false;
        }

        wchar_t buffer[MAX_PATH_SIZE] = {0};
        DWORD size = MAX_PATH_SIZE;

        BOOL result = QueryFullProcessImageNameW(hProcess, 0, buffer, &size);
        CloseHandle(hProcess);

        if (result)
        {
            path = buffer;
            return true;
        }

        return false;
    }
}

int EnumProcessesNative(uint32_t* pids, uint32_t maxCount, uint32_t* returnedCount)
{
    if (pids == nullptr || returnedCount == nullptr || maxCount == 0)
    {
        return 0;
    }

    *returnedCount = 0;

    std::vector<DWORD> pidBuffer(4096);
    DWORD bytesReturned = 0;

    if (!EnumProcesses(pidBuffer.data(), static_cast<DWORD>(pidBuffer.size() * sizeof(DWORD)), &bytesReturned))
    {
        return 0;
    }

    DWORD processCount = bytesReturned / sizeof(DWORD);
    uint32_t copyCount = static_cast<uint32_t>((std::min)(processCount, static_cast<DWORD>(maxCount)));

    for (uint32_t i = 0; i < copyCount; ++i)
    {
        pids[i] = pidBuffer[i];
    }

    *returnedCount = copyCount;
    return 1;
}

int GetProcessPathById(uint32_t pid, wchar_t* path, uint32_t pathSize)
{
    if (path == nullptr || pathSize == 0)
    {
        return 0;
    }

    path[0] = L'\0';

    std::wstring processPath;
    if (GetProcessPathInternal(pid, processPath))
    {
        if (processPath.size() < pathSize)
        {
            wcscpy_s(path, pathSize, processPath.c_str());
            return 1;
        }
    }

    return 0;
}

void MonitorProcesses(NewProcessCallback callback, void* userData, volatile int* stopFlag)
{
    if (callback == nullptr || stopFlag == nullptr)
    {
        return;
    }

    std::set<uint32_t> knownProcesses = GetProcessSet();

    while (!(*stopFlag))
    {
        Sleep(MONITOR_INTERVAL_MS);

        if (*stopFlag)
        {
            break;
        }

        std::set<uint32_t> currentProcesses = GetProcessSet();

        for (uint32_t pid : currentProcesses)
        {
            if (knownProcesses.find(pid) == knownProcesses.end())
            {
                std::wstring path;
                GetProcessPathInternal(pid, path);

                const wchar_t* pathPtr = path.empty() ? L"" : path.c_str();
                callback(pid, pathPtr, userData);

                knownProcesses.insert(pid);
            }
        }
    }
}
