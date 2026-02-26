#pragma once

#include <cstdint>

extern "C"
{
    __declspec(dllexport) bool ReadBootSector(int driveIndex, uint8_t* buffer, uint32_t bufferSize);
    __declspec(dllexport) bool ReadVolumeBootRecord(const wchar_t* driveLetter, uint8_t* buffer, uint32_t bufferSize);
}
