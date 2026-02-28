#pragma once

#include <cstdint>

typedef void (*NewProcessCallback)(uint32_t pid, const wchar_t* path, void* userData);

extern "C"
{
    __declspec(dllexport) int EnumProcessesNative(uint32_t* pids, uint32_t maxCount, uint32_t* returnedCount);
    __declspec(dllexport) int GetProcessPathById(uint32_t pid, wchar_t* path, uint32_t pathSize);
    __declspec(dllexport) void MonitorProcesses(NewProcessCallback callback, void* userData, volatile int* stopFlag);
}
