#include "pch.h"
#include "SystemInfo.hpp"

#include <string>
#include <array>
#include <cwchar>

namespace
{
    struct MemoryStatusEx
    {
        uint32_t dwLength;
        uint32_t dwMemoryLoad;
        uint64_t ullTotalPhys;
        uint64_t ullAvailPhys;
        uint64_t ullTotalPageFile;
        uint64_t ullAvailPageFile;
        uint64_t ullTotalVirtual;
        uint64_t ullAvailVirtual;
        uint64_t ullAvailExtendedVirtual;
    };

    bool GlobalMemoryStatusExNative(MemoryStatusEx* status)
    {
        using FnGlobalMemoryStatusEx = BOOL(WINAPI*)(MemoryStatusEx*);
        
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            return false;
        }

        FnGlobalMemoryStatusEx fn = reinterpret_cast<FnGlobalMemoryStatusEx>(
            GetProcAddress(kernel32, "GlobalMemoryStatusEx")
        );

        if (fn == nullptr)
        {
            return false;
        }

        status->dwLength = sizeof(MemoryStatusEx);
        return fn(status) != FALSE;
    }

    void FormatMemorySize(uint64_t bytes, double& value, int& unitIndex)
    {
        constexpr std::array<const wchar_t*, 4> units = { L"B", L"KB", L"MB", L"GB" };
        unitIndex = 0;
        value = static_cast<double>(bytes);

        while (value >= 1024.0 && unitIndex < static_cast<int>(units.size() - 1))
        {
            value /= 1024.0;
            unitIndex++;
        }
    }

    void FormatMemorySizeFromDouble(double bytes, double& value, int& unitIndex)
    {
        constexpr std::array<const wchar_t*, 4> units = { L"B", L"KB", L"MB", L"GB" };
        unitIndex = 0;
        value = bytes;

        while (value >= 1024.0 && unitIndex < static_cast<int>(units.size() - 1))
        {
            value /= 1024.0;
            unitIndex++;
        }
    }
}

bool GetMemoryInfo(uint32_t* loadPercent, wchar_t* display, uint32_t displaySize)
{
    if (loadPercent == nullptr || display == nullptr || displaySize == 0)
    {
        return false;
    }

    MemoryStatusEx status{};
    if (!GlobalMemoryStatusExNative(&status))
    {
        return false;
    }

    *loadPercent = status.dwMemoryLoad;

    uint64_t totalPhys = status.ullTotalPhys;
    uint64_t availPhys = status.ullAvailPhys;
    uint64_t usedPhys = totalPhys - availPhys;

    double totalValue = 0.0;
    double usedValue = 0.0;
    int unitIndex = 0;

    FormatMemorySize(totalPhys, totalValue, unitIndex);

    double usedValueInput = static_cast<double>(usedPhys);
    int usedUnitIndex = 0;
    FormatMemorySizeFromDouble(usedValueInput, usedValue, usedUnitIndex);

    while (usedUnitIndex < unitIndex)
    {
        usedValue /= 1024.0;
        usedUnitIndex++;
    }

    constexpr std::array<const wchar_t*, 4> units = { L"B", L"KB", L"MB", L"GB" };

    _snwprintf_s(
        display,
        displaySize,
        _TRUNCATE,
        L"%.1f %s / %.1f %s (%u%%)",
        usedValue,
        units[unitIndex],
        totalValue,
        units[unitIndex],
        status.dwMemoryLoad
    );

    return true;
}
