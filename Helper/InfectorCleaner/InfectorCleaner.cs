namespace Helper.InfectorCleaner
{
    public sealed class CleaningResult
    {
        public Boolean Success { get; set; }
        public String Message { get; set; } = String.Empty;
        public UInt32? OriginalEntryPoint { get; set; }
        public String? MaliciousSection { get; set; }
        public String? BackupPath { get; set; }
        public String? QuarantineId { get; set; }
        public Byte[]? OriginalFileData { get; set; }
        public List<String> CleaningLog { get; set; } = [];

        public static CleaningResult Succeed(String message) => new() { Success = true, Message = message };
        public static CleaningResult Fail(String message) => new() { Success = false, Message = message };
    }

    public sealed class PEFileInfo
    {
        public Byte[] Data { get; set; } = [];
        public Int32 PeOffset { get; set; }
        public Int32 CoffHeaderOffset { get; set; }
        public Int32 OptionalHeaderOffset { get; set; }
        public Int32 SectionTableOffset { get; set; }
        public UInt16 NumSections { get; set; }
        public UInt16 OptionalHeaderSize { get; set; }
        public UInt32 EntryPoint { get; set; }
        public UInt64 ImageBase { get; set; }
        public Boolean Is64Bit { get; set; }
        public List<SectionInfoRaw> Sections { get; set; } = [];
    }

    public sealed class InfectionAnalysis
    {
        public Boolean IsInfected { get; set; }
        public Int32? MaliciousSectionIndex { get; set; }
        public String? MaliciousSectionName { get; set; }
        public UInt32? OriginalEntryPoint { get; set; }
        public List<String> Indicators { get; set; } = [];
    }

    public static class InfectorCleaner
    {
        public static PEFileInfo? AnalyzePeStructure(String filePath)
        {
            try
            {
                Byte[] data = File.ReadAllBytes(filePath);
                return AnalyzePeStructureFromBytes(data);
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static PEFileInfo? AnalyzePeStructureFromBytes(Byte[] data)
        {
            if (data.Length < 64)
                return null;

            if (data[0] != 0x4D || data[1] != 0x5A)
                return null;

            Int32 peOffset = BitConverter.ToInt32(data, 60);
            if (peOffset + 24 > data.Length)
                return null;

            if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45)
                return null;

            Int32 coffHeaderOffset = peOffset + 4;
            UInt16 numSections = BitConverter.ToUInt16(data, coffHeaderOffset + 2);
            UInt16 optionalHeaderSize = BitConverter.ToUInt16(data, coffHeaderOffset + 16);
            Int32 optionalHeaderOffset = coffHeaderOffset + 20;

            UInt16 peType = BitConverter.ToUInt16(data, optionalHeaderOffset);
            Boolean is64Bit = peType == 0x20B;

            UInt32 entryPoint = BitConverter.ToUInt32(data, optionalHeaderOffset + 16);

            UInt64 imageBase;
            if (is64Bit)
            {
                imageBase = BitConverter.ToUInt64(data, optionalHeaderOffset + 24);
            }
            else
            {
                imageBase = BitConverter.ToUInt32(data, optionalHeaderOffset + 28);
            }

            Int32 sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;

            var sections = new List<SectionInfoRaw>();
            for (Int32 i = 0; i < numSections; i++)
            {
                Int32 sectionOffset = sectionTableOffset + (i * 40);
                if (sectionOffset + 40 > data.Length)
                    break;

                String name = System.Text.Encoding.ASCII.GetString(data, sectionOffset, 8).TrimEnd('\0');
                UInt32 virtualSize = BitConverter.ToUInt32(data, sectionOffset + 8);
                UInt32 virtualAddress = BitConverter.ToUInt32(data, sectionOffset + 12);
                UInt32 rawSize = BitConverter.ToUInt32(data, sectionOffset + 16);
                UInt32 rawAddress = BitConverter.ToUInt32(data, sectionOffset + 20);
                UInt32 characteristics = BitConverter.ToUInt32(data, sectionOffset + 36);

                sections.Add(new SectionInfoRaw(name, virtualSize, virtualAddress, rawSize, rawAddress, characteristics, i));
            }

            return new PEFileInfo
            {
                Data = data,
                PeOffset = peOffset,
                CoffHeaderOffset = coffHeaderOffset,
                OptionalHeaderOffset = optionalHeaderOffset,
                SectionTableOffset = sectionTableOffset,
                NumSections = numSections,
                OptionalHeaderSize = optionalHeaderSize,
                EntryPoint = entryPoint,
                ImageBase = imageBase,
                Is64Bit = is64Bit,
                Sections = sections
            };
        }

        public static InfectionAnalysis AnalyzeInfection(PEFileInfo peInfo)
        {
            var analysis = new InfectionAnalysis();

            if (peInfo.Sections.Count == 0)
                return analysis;

            var lastSection = peInfo.Sections[^1];
            Int32 lastSectionIndex = peInfo.Sections.Count - 1;

            UInt32 lastSectionStart = lastSection.VirtualAddress;
            UInt32 lastSectionEnd = lastSection.VirtualAddress + lastSection.VirtualSize;
            Boolean entryPointInLastSection = peInfo.EntryPoint >= lastSectionStart && peInfo.EntryPoint < lastSectionEnd;

            Boolean isStandardCodeSection = lastSection.Name == ".text" ||
                lastSection.Name.StartsWith(".text") ||
                (lastSection.Characteristics & 0x00000020) != 0;

            Boolean isExecutable = (lastSection.Characteristics & 0x20000000) != 0;
            Boolean isRwe = (lastSection.Characteristics & 0xE0000000) == 0xE0000000;

            Boolean entryPointInText = false;
            foreach (var section in peInfo.Sections)
            {
                if (section.Name == ".text" || section.Name.StartsWith(".text"))
                {
                    UInt32 textStart = section.VirtualAddress;
                    UInt32 textEnd = section.VirtualAddress + section.VirtualSize;
                    if (peInfo.EntryPoint >= textStart && peInfo.EntryPoint < textEnd)
                    {
                        entryPointInText = true;
                        break;
                    }
                }
            }

            Int32 score = 0;

            if (entryPointInLastSection && !isStandardCodeSection)
            {
                analysis.Indicators.Add($"Entry point points to last section '{lastSection.Name}' (non-standard code section)");
                score += 35;
            }

            if (isExecutable && lastSection.RawSize > 0)
            {
                Int32 rawDataStart = (Int32)lastSection.RawAddress;
                Int32 rawDataEnd = rawDataStart + (Int32)lastSection.RawSize;
                if (rawDataStart >= 0 && rawDataEnd <= peInfo.Data.Length)
                {
                    Single entropy = InfectorDetector.CalculateEntropy(peInfo.Data, rawDataStart, rawDataEnd);
                    if (entropy > 7.5f)
                    {
                        analysis.Indicators.Add($"Last section '{lastSection.Name}' is executable with high entropy: {entropy:F2}");
                        score += 25;
                    }
                }
            }

            if (lastSection.RawSize > 0 && lastSection.VirtualSize > 0)
            {
                Single ratio = (Single)lastSection.VirtualSize / lastSection.RawSize;
                if (ratio > 5.0f)
                {
                    analysis.Indicators.Add($"Last section size anomaly: VSize={lastSection.VirtualSize} RSize={lastSection.RawSize} Ratio={ratio:F1}");
                    score += 20;
                }
            }

            if (!entryPointInText && entryPointInLastSection)
            {
                analysis.Indicators.Add("Entry point is not in .text section but in the last section");
                score += 30;
            }

            if (isRwe)
            {
                analysis.Indicators.Add($"Last section '{lastSection.Name}' has RWE permissions");
                score += 25;
            }

            Int32 threshold = 50;
            Boolean hasMultipleIndicators = analysis.Indicators.Count >= 2;

            if (score >= threshold && hasMultipleIndicators)
            {
                analysis.MaliciousSectionIndex = lastSectionIndex;
                analysis.MaliciousSectionName = lastSection.Name;

                UInt32? oep = ExtractOriginalEntryPoint(peInfo, lastSectionIndex);
                if (oep.HasValue)
                {
                    analysis.OriginalEntryPoint = oep;
                    analysis.Indicators.Add($"Extracted original entry point from virus code: 0x{oep.Value:X8}");
                }

                analysis.IsInfected = true;
            }

            return analysis;
        }

        public static UInt32? ExtractOriginalEntryPoint(PEFileInfo peInfo, Int32 maliciousSectionIndex)
        {
            if (maliciousSectionIndex < 0 || maliciousSectionIndex >= peInfo.Sections.Count)
                return null;

            var section = peInfo.Sections[maliciousSectionIndex];

            if (section.RawAddress == 0 || section.RawSize == 0)
                return null;

            Int32 start = (Int32)section.RawAddress;
            Int32 end = start + (Int32)section.RawSize;

            if (end > peInfo.Data.Length)
                return null;

            Byte[] code = peInfo.Data;

            for (Int32 i = 0; i < end - 10; i++)
            {
                if (code[i] == 0x49 && code[i + 1] == 0xFF && code[i + 2] == 0xE7)
                {
                    if (i >= 10)
                    {
                        for (Int32 j = i - 1; j >= 0; j--)
                        {
                            if (code[j] == 0x49 && code[j + 1] == 0xBF && j + 10 <= i)
                            {
                                UInt64 addr = BitConverter.ToUInt64(code, j + 2);
                                UInt32 rva = (UInt32)(addr - peInfo.ImageBase);
                                return rva;
                            }
                        }
                    }
                }

                if (code[i] == 0x48 && code[i + 1] == 0xB8)
                {
                    if (i + 10 < end && code[i + 10] == 0xFF && code[i + 11] == 0xE0)
                    {
                        UInt64 addr = BitConverter.ToUInt64(code, i + 2);
                        UInt32 rva = (UInt32)(addr - peInfo.ImageBase);
                        return rva;
                    }
                }
            }

            if (end - start >= 20)
            {
                for (Int32 i = start; i < end - 4; i++)
                {
                    UInt32 val = BitConverter.ToUInt32(code, i);
                    if (val >= 0x1000 && val < 0x10000000)
                    {
                        foreach (var sec in peInfo.Sections)
                        {
                            if (sec.Name == ".text" || sec.Name.StartsWith(".text"))
                            {
                                UInt32 secStart = sec.VirtualAddress;
                                UInt32 secEnd = sec.VirtualAddress + sec.VirtualSize;
                                if (val >= secStart && val < secEnd)
                                    return val;
                            }
                        }
                    }
                }
            }

            return null;
        }

        public static Boolean RestoreEntryPoint(PEFileInfo peInfo, UInt32 originalEp)
        {
            Int32 offset = peInfo.OptionalHeaderOffset + 16;

            if (offset + 4 > peInfo.Data.Length)
                return false;

            peInfo.Data[offset] = (Byte)(originalEp & 0xFF);
            peInfo.Data[offset + 1] = (Byte)((originalEp >> 8) & 0xFF);
            peInfo.Data[offset + 2] = (Byte)((originalEp >> 16) & 0xFF);
            peInfo.Data[offset + 3] = (Byte)((originalEp >> 24) & 0xFF);

            peInfo.EntryPoint = originalEp;
            return true;
        }

        public static Boolean RemoveMaliciousSection(PEFileInfo peInfo, Int32 maliciousIndex)
        {
            if (maliciousIndex < 0 || maliciousIndex >= peInfo.Sections.Count)
                return false;

            peInfo.Sections.RemoveAt(maliciousIndex);

            peInfo.NumSections = (UInt16)peInfo.Sections.Count;

            Int32 numSectionsOffset = peInfo.CoffHeaderOffset + 2;
            peInfo.Data[numSectionsOffset] = (Byte)(peInfo.NumSections & 0xFF);
            peInfo.Data[numSectionsOffset + 1] = (Byte)((peInfo.NumSections >> 8) & 0xFF);

            for (Int32 i = 0; i < peInfo.Sections.Count; i++)
            {
                peInfo.Sections[i].Index = i;
            }

            for (Int32 i = maliciousIndex; i < peInfo.Sections.Count; i++)
            {
                Int32 srcOffset = peInfo.SectionTableOffset + ((i + 1) * 40);
                Int32 dstOffset = peInfo.SectionTableOffset + (i * 40);

                if (srcOffset + 40 <= peInfo.Data.Length && dstOffset + 40 <= peInfo.Data.Length)
                {
                    Array.Copy(peInfo.Data, srcOffset, peInfo.Data, dstOffset, 40);
                }
            }

            Int32 lastEntryOffset = peInfo.SectionTableOffset + (peInfo.Sections.Count * 40);
            if (lastEntryOffset + 40 <= peInfo.Data.Length)
            {
                Array.Clear(peInfo.Data, lastEntryOffset, 40);
            }

            return true;
        }

        public static Boolean RepairFileStructure(PEFileInfo peInfo)
        {
            Int32 sizeOfImageOffset = peInfo.OptionalHeaderOffset + 56;

            if (sizeOfImageOffset + 4 <= peInfo.Data.Length)
            {
                UInt32 newSize;
                if (peInfo.Sections.Count > 0)
                {
                    var last = peInfo.Sections[^1];
                    UInt32 size = last.VirtualAddress + last.VirtualSize;
                    newSize = ((size + 0xFFF) / 0x1000) * 0x1000;
                }
                else
                {
                    return false;
                }

                peInfo.Data[sizeOfImageOffset] = (Byte)(newSize & 0xFF);
                peInfo.Data[sizeOfImageOffset + 1] = (Byte)((newSize >> 8) & 0xFF);
                peInfo.Data[sizeOfImageOffset + 2] = (Byte)((newSize >> 16) & 0xFF);
                peInfo.Data[sizeOfImageOffset + 3] = (Byte)((newSize >> 24) & 0xFF);
            }

            UInt32 truncatePos = 0;
            foreach (var section in peInfo.Sections)
            {
                UInt32 sectionEnd = section.RawAddress + section.RawSize;
                if (sectionEnd > truncatePos)
                    truncatePos = sectionEnd;
            }

            if (truncatePos > 0 && truncatePos < peInfo.Data.Length)
            {
                Byte[] newData = new Byte[truncatePos];
                Array.Copy(peInfo.Data, newData, (Int32)truncatePos);
                peInfo.Data = newData;
            }

            return true;
        }

        public static CleaningResult CleanInfectedFile(String filePath)
        {
            var cleaningLog = new List<String>();

            cleaningLog.Add($"[1/6] Start processing infector: {filePath}");

            var infectorResult = InfectorDetector.DetectInfector(filePath);

            if (!infectorResult.IsInfected)
            {
                cleaningLog.Add("[ERROR] No infector virus characteristics detected");
                var failResult = CleaningResult.Fail("No infector virus characteristics detected");
                failResult.CleaningLog = cleaningLog;
                return failResult;
            }

            cleaningLog.Add($"[2/6] Infector virus detected, confidence: {infectorResult.Confidence * 100.0f:F2}%");

            var peInfo = AnalyzePeStructure(filePath);
            if (peInfo == null)
            {
                cleaningLog.Add("[ERROR] PE parsing failed");
                var failResult = CleaningResult.Fail("PE parsing failed");
                failResult.CleaningLog = cleaningLog;
                return failResult;
            }

            cleaningLog.Add($"[3/6] PE file parsed successfully: {peInfo.NumSections} sections");

            var analysis = AnalyzeInfection(peInfo);

            Int32 maliciousIndex;
            if (analysis.IsInfected && analysis.MaliciousSectionIndex.HasValue)
            {
                maliciousIndex = analysis.MaliciousSectionIndex.Value;
            }
            else
            {
                maliciousIndex = peInfo.Sections.Count - 1;
            }

            var maliciousSection = peInfo.Sections[maliciousIndex];
            cleaningLog.Add($"  - Malicious section: {maliciousSection.Name} (index: {maliciousIndex})");

            UInt32 originalEp;
            if (analysis.IsInfected && analysis.OriginalEntryPoint.HasValue)
            {
                originalEp = analysis.OriginalEntryPoint.Value;
                cleaningLog.Add($"  - Extracted original entry point from virus code: 0x{originalEp:X8}");
            }
            else
            {
                UInt32? foundEp = null;
                foreach (var section in peInfo.Sections)
                {
                    if (section.Name == ".text" || section.Name.StartsWith(".text"))
                    {
                        foundEp = section.VirtualAddress;
                        break;
                    }
                }

                if (foundEp.HasValue)
                {
                    originalEp = foundEp.Value;
                    cleaningLog.Add($"  - Using .text section address as original entry point: 0x{originalEp:X8}");
                }
                else
                {
                    cleaningLog.Add("[ERROR] Cannot determine original entry point");
                    var failResult = CleaningResult.Fail("Cannot determine original entry point");
                    failResult.CleaningLog = cleaningLog;
                    return failResult;
                }
            }

            cleaningLog.Add("[4/6] Backing up original file to quarantine...");

            Byte[]? originalFileData = null;
            try
            {
                originalFileData = File.ReadAllBytes(filePath);
                cleaningLog.Add("  - Original file data captured for quarantine");
            }
            catch (Exception ex)
            {
                cleaningLog.Add($"[WARNING] Failed to read original file for backup: {ex.Message}, continuing cleanup");
            }

            cleaningLog.Add("[5/6] Cleaning infection...");

            if (!RestoreEntryPoint(peInfo, originalEp))
            {
                cleaningLog.Add("[ERROR] Failed to restore entry point");
                var failResult = CleaningResult.Fail("Failed to restore entry point");
                failResult.CleaningLog = cleaningLog;
                return failResult;
            }
            cleaningLog.Add($"  - Entry point restored: 0x{originalEp:X8}");

            UInt32 maliciousRawSize = maliciousSection.RawSize;

            if (!RemoveMaliciousSection(peInfo, maliciousIndex))
            {
                cleaningLog.Add("[ERROR] Failed to remove malicious section");
                var failResult = CleaningResult.Fail("Failed to remove malicious section");
                failResult.CleaningLog = cleaningLog;
                return failResult;
            }
            cleaningLog.Add($"  - Malicious section '{maliciousSection.Name}' removed");

            if (!RepairFileStructure(peInfo))
            {
                cleaningLog.Add("[ERROR] Failed to repair file structure");
                var failResult = CleaningResult.Fail("Failed to repair file structure");
                failResult.CleaningLog = cleaningLog;
                return failResult;
            }
            cleaningLog.Add("  - File structure repaired");

            try
            {
                string tempFile = filePath + ".cleaned";
                File.WriteAllBytes(tempFile, peInfo.Data);
                File.Copy(tempFile, filePath, true);
                File.Delete(tempFile);
                cleaningLog.Add($"  - Repaired file saved: {filePath}");
            }
            catch (Exception ex)
            {
                cleaningLog.Add($"[ERROR] Failed to save repaired file: {ex.Message}");
                var failResult = CleaningResult.Fail($"Failed to save repaired file: {ex.Message}");
                failResult.CleaningLog = cleaningLog;
                return failResult;
            }

            cleaningLog.Add("[6/6] Cleanup complete");

            var result = CleaningResult.Succeed(
                $"Successfully cleaned infector virus. Malicious section '{maliciousSection.Name}' removed, entry point restored to 0x{originalEp:X8}");

            result.OriginalEntryPoint = originalEp;
            result.MaliciousSection = maliciousSection.Name;
            result.OriginalFileData = originalFileData;
            result.CleaningLog = cleaningLog;

            return result;
        }
    }
}
