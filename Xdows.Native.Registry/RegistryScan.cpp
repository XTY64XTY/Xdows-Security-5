#include "pch.h"
#include "RegistryScan.hpp"

#include <string>
#include <vector>
#include <algorithm>

namespace
{
    const std::vector<std::wstring>& GetSuspiciousKeys()
    {
        static const std::vector<std::wstring> keys = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppInit_DLLs",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",
            L"SOFTWARE\\Policies\\Microsoft\\MMC",
            L"SOFTWARE\\Classes",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies",
            L"Software\\Classes\\ms-settings\\Shell\\Open\\command"
        };
        return keys;
    }

    std::wstring ToLower(const std::wstring& str)
    {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }

    bool IsSuspiciousKey(const std::wstring& keyPath)
    {
        std::wstring keyPathLower = ToLower(keyPath);
        
        for (const auto& suspiciousKey : GetSuspiciousKeys())
        {
            std::wstring suspiciousKeyLower = ToLower(suspiciousKey);
            if (keyPathLower.find(suspiciousKeyLower) != std::wstring::npos)
            {
                return true;
            }
        }
        
        return false;
    }
}

int ScanRegistryKey(const wchar_t* keyPath, wchar_t* threatType, uint32_t threatTypeSize)
{
    if (keyPath == nullptr || threatType == nullptr || threatTypeSize == 0)
    {
        return 0;
    }

    threatType[0] = L'\0';

    std::wstring keyPathStr(keyPath);

    if (IsSuspiciousKey(keyPathStr))
    {
        const wchar_t* threatName = L"Xdows.Local.RegistryScan";
        size_t threatNameLen = wcslen(threatName);
        
        if (threatTypeSize > threatNameLen)
        {
            wcscpy_s(threatType, threatTypeSize, threatName);
        }
        
        return 1;
    }

    return 0;
}
