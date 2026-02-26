#include "pch.h"
#include "TrustManagerNative.hpp"

#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>

#include <bcrypt.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    const uint32_t SHA256_HASH_SIZE = 32;
    const uint32_t SHA256_STRING_SIZE = 65;
    const uint32_t READ_BUFFER_SIZE = 65536;

    bool ComputeSha256(const std::vector<uint8_t>& data, std::wstring& hashString)
    {
        hashString.clear();

        NTSTATUS status = BCryptOpenAlgorithmProvider(nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            return false;
        }

        BCRYPT_HASH_HANDLE hHash = nullptr;
        status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        status = BCryptHashData(hHash, const_cast<uint8_t*>(data.data()), static_cast<uint32_t>(data.size()), 0);
        if (!BCRYPT_SUCCESS(status))
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        std::vector<uint8_t> hashBuffer(SHA256_HASH_SIZE);
        status = BCryptFinishHash(hHash, hashBuffer.data(), static_cast<uint32_t>(hashBuffer.size()), 0);

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (!BCRYPT_SUCCESS(status))
        {
            return false;
        }

        std::wostringstream oss;
        for (uint8_t byte : hashBuffer)
        {
            oss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(byte);
        }

        hashString = oss.str();
        return true;
    }

    bool ComputeFileSha256(const wchar_t* filePath, std::wstring& hashString)
    {
        hashString.clear();

        HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        NTSTATUS status = BCryptOpenAlgorithmProvider(nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            CloseHandle(hFile);
            return false;
        }

        BCRYPT_HASH_HANDLE hHash = nullptr;
        status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status))
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return false;
        }

        std::vector<uint8_t> buffer(READ_BUFFER_SIZE);
        DWORD bytesRead = 0;
        bool success = true;

        while (ReadFile(hFile, buffer.data(), static_cast<uint32_t>(buffer.size()), &bytesRead, nullptr) && bytesRead > 0)
        {
            status = BCryptHashData(hHash, buffer.data(), bytesRead, 0);
            if (!BCRYPT_SUCCESS(status))
            {
                success = false;
                break;
            }
        }

        CloseHandle(hFile);

        if (!success)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        std::vector<uint8_t> hashBuffer(SHA256_HASH_SIZE);
        status = BCryptFinishHash(hHash, hashBuffer.data(), static_cast<uint32_t>(hashBuffer.size()), 0);

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (!BCRYPT_SUCCESS(status))
        {
            return false;
        }

        std::wostringstream oss;
        for (uint8_t byte : hashBuffer)
        {
            oss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(byte);
        }

        hashString = oss.str();
        return true;
    }

    std::wstring ToLower(const std::wstring& str)
    {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    }
}

int CalculateFileSha256(const wchar_t* filePath, wchar_t* hash, uint32_t hashSize)
{
    if (filePath == nullptr || hash == nullptr || hashSize < SHA256_STRING_SIZE)
    {
        return 0;
    }

    hash[0] = L'\0';

    std::wstring hashString;
    if (ComputeFileSha256(filePath, hashString))
    {
        wcscpy_s(hash, hashSize, hashString.c_str());
        return 1;
    }

    return 0;
}

int IsFileTrusted(const wchar_t* filePath, const wchar_t* trustFolderPath)
{
    if (filePath == nullptr || trustFolderPath == nullptr)
    {
        return 0;
    }

    std::wstring fileHash;
    if (!ComputeFileSha256(filePath, fileHash))
    {
        return 0;
    }

    std::wstring trustFile = trustFolderPath;
    if (!trustFile.empty() && trustFile.back() != L'\\')
    {
        trustFile += L'\\';
    }
    trustFile += ToLower(fileHash) + L".json";

    DWORD attributes = GetFileAttributesW(trustFile.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
}

int CreateTrustItemJson(const wchar_t* filePath, const wchar_t* hash, wchar_t* json, uint32_t jsonSize)
{
    if (filePath == nullptr || hash == nullptr || json == nullptr || jsonSize == 0)
    {
        return 0;
    }

    json[0] = L'\0';

    try
    {
        nlohmann::json j;
        
        int pathLen = WideCharToMultiByte(CP_UTF8, 0, filePath, -1, nullptr, 0, nullptr, nullptr);
        std::string pathUtf8(pathLen - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, filePath, -1, pathUtf8.data(), pathLen, nullptr, nullptr);
        j["SourcePath"] = pathUtf8;
        
        int hashLen = WideCharToMultiByte(CP_UTF8, 0, hash, -1, nullptr, 0, nullptr, nullptr);
        std::string hashUtf8(hashLen - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, hash, -1, hashUtf8.data(), hashLen, nullptr, nullptr);
        j["Hash"] = hashUtf8;

        std::string jsonStr = j.dump();
        std::wstring jsonWStr(jsonStr.begin(), jsonStr.end());

        if (jsonWStr.size() < jsonSize)
        {
            wcscpy_s(json, jsonSize, jsonWStr.c_str());
            return 1;
        }
    }
    catch (...)
    {
        return 0;
    }

    return 0;
}
