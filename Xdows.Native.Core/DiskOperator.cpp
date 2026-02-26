#include "pch.h"
#include "DiskOperator.hpp"

#include <string>

namespace
{
    const uint32_t SECTOR_SIZE = 512;

    std::pair<void*, bool> OpenDevice(const std::wstring& devicePath)
    {
        HANDLE handle = CreateFileW(
            devicePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (handle == INVALID_HANDLE_VALUE)
        {
            return { nullptr, false };
        }

        return { handle, true };
    }

    bool ReadSectorInternal(HANDLE handle, uint8_t* buffer, uint32_t sectorSize)
    {
        DWORD bytesRead = 0;
        BOOL result = ReadFile(handle, buffer, sectorSize, &bytesRead, nullptr);

        if (!result || bytesRead != sectorSize)
        {
            return false;
        }

        return true;
    }
}

bool ReadBootSector(int driveIndex, uint8_t* buffer, uint32_t bufferSize)
{
    if (buffer == nullptr || bufferSize < SECTOR_SIZE)
    {
        return false;
    }

    std::wstring devicePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveIndex);

    auto [handle, success] = OpenDevice(devicePath);
    if (!success)
    {
        return false;
    }

    bool result = ReadSectorInternal(handle, buffer, SECTOR_SIZE);
    CloseHandle(handle);

    return result;
}

bool ReadVolumeBootRecord(const wchar_t* driveLetter, uint8_t* buffer, uint32_t bufferSize)
{
    if (driveLetter == nullptr || buffer == nullptr || bufferSize < SECTOR_SIZE)
    {
        return false;
    }

    std::wstring letter(driveLetter);
    while (!letter.empty() && (letter.back() == L':' || letter.back() == L' '))
    {
        letter.pop_back();
    }

    if (letter.empty())
    {
        return false;
    }

    std::wstring devicePath = L"\\\\.\\" + letter + L":";

    auto [handle, success] = OpenDevice(devicePath);
    if (!success)
    {
        return false;
    }

    bool result = ReadSectorInternal(handle, buffer, SECTOR_SIZE);
    CloseHandle(handle);

    return result;
}
