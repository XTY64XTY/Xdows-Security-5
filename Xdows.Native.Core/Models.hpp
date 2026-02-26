#pragma once

#include <cstdint>
#include <cstddef>

struct TrustItem
{
    wchar_t SourcePath[260];
    wchar_t Hash[65];
};

struct QuarantineItem
{
    wchar_t FileHash[65];
    wchar_t SourcePath[260];
    wchar_t ThreatName[128];
    wchar_t EncryptionKey[49];
    wchar_t IV[33];
    uint8_t* EncryptedData;
    size_t DataSize;
};

struct PluginMetadata
{
    wchar_t Id[64];
    wchar_t Name[128];
    wchar_t Description[256];
    wchar_t Author[64];
    wchar_t Version[16];
    wchar_t Requires[64];
};
