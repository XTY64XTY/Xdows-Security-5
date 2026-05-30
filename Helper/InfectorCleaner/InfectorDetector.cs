using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Helper.InfectorCleaner
{
    public sealed class InfectorDetectionResult
    {
        public Boolean IsInfected { get; set; }
        public Single Confidence { get; set; }
        public List<String> Indicators { get; set; } = [];
        public Single Entropy { get; set; }
        public List<String> SuspiciousSections { get; set; } = [];
        public Boolean EntryPointAnomaly { get; set; }
        public Boolean SectionMismatch { get; set; }
        public List<String> HighEntropySections { get; set; } = [];

        public static InfectorDetectionResult Clean() => new();
    }

    public static class InfectorDetector
    {
        private static readonly HashSet<String> s_peExtensions = new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr" };
        private static readonly HashSet<String> s_excludedExtensions = new(StringComparer.OrdinalIgnoreCase) { ".sys", ".dll", ".drv" };

        public static InfectorDetectionResult DetectInfector(String filePath)
        {
            String ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (!s_peExtensions.Contains(ext))
                return InfectorDetectionResult.Clean();

            if (s_excludedExtensions.Contains(ext))
                return InfectorDetectionResult.Clean();

            try
            {
                Byte[] data = File.ReadAllBytes(filePath);
                return AnalyzePeInfector(data);
            }
            catch (Exception)
            {
                return InfectorDetectionResult.Clean();
            }
        }

        public static InfectorDetectionResult DetectInfectorFromBytes(Byte[] data, String filePath)
        {
            String ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (!s_peExtensions.Contains(ext))
                return InfectorDetectionResult.Clean();

            if (s_excludedExtensions.Contains(ext))
                return InfectorDetectionResult.Clean();

            return AnalyzePeInfector(data);
        }

        private static InfectorDetectionResult AnalyzePeInfector(Byte[] data)
        {
            var result = InfectorDetectionResult.Clean();
            var indicators = new List<String>();
            Single score = 0;

            if (data.Length < 64)
                return result;

            if (data[0] != 0x4D || data[1] != 0x5A)
                return result;

            Int32 peOffset = BitConverter.ToInt32(data, 60);
            if (peOffset + 24 >= data.Length)
                return result;

            if (data[peOffset] != 0x50 || data[peOffset + 1] != 0x45)
                return result;

            Int32 coffHeaderOffset = peOffset + 4;
            UInt16 numSections = BitConverter.ToUInt16(data, coffHeaderOffset + 2);

            if (numSections < 2 || numSections > 20)
                return result;

            UInt16 optionalHeaderSize = BitConverter.ToUInt16(data, coffHeaderOffset + 16);
            Int32 optionalHeaderOffset = coffHeaderOffset + 20;
            UInt32 entryPoint = BitConverter.ToUInt32(data, optionalHeaderOffset + 16);

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

            if (sections.Count == 0)
                return result;

            var lastSection = sections[^1];
            UInt32 lastSectionStart = lastSection.VirtualAddress;
            UInt32 lastSectionEnd = lastSection.VirtualAddress + lastSection.VirtualSize;
            Boolean entryPointInLastSection = entryPoint >= lastSectionStart && entryPoint < lastSectionEnd;

            SectionInfoRaw? entryPointSection = null;
            foreach (var section in sections)
            {
                UInt32 secStart = section.VirtualAddress;
                UInt32 secEnd = section.VirtualAddress + section.VirtualSize;
                if (entryPoint >= secStart && entryPoint < secEnd)
                {
                    entryPointSection = section;
                    break;
                }
            }

            if (entryPointSection != null)
            {
                Boolean isStandardCodeSection = entryPointSection.Name == ".text" ||
                    entryPointSection.Name.StartsWith(".text") ||
                    entryPointSection.Name.StartsWith("CODE") ||
                    (entryPointSection.Characteristics & 0x00000020) != 0;

                if (!isStandardCodeSection)
                {
                    indicators.Add($"Entry point points to non-standard section '{entryPointSection.Name}'");
                    result.EntryPointAnomaly = true;
                    score += 35.0f;
                }

                Boolean epSectionExecutable = (entryPointSection.Characteristics & 0x20000000) != 0;

                if (epSectionExecutable && entryPointSection.RawSize > 0)
                {
                    Int32 rawDataStart = (Int32)entryPointSection.RawAddress;
                    Int32 rawDataEnd = rawDataStart + (Int32)entryPointSection.RawSize;
                    if (rawDataStart >= 0 && rawDataEnd <= data.Length)
                    {
                        Single entropy = CalculateEntropy(data, rawDataStart, rawDataEnd);
                        if (entropy > 7.5f)
                        {
                            indicators.Add($"Entry point section '{entryPointSection.Name}' is executable with high entropy: {entropy:F2}");
                            result.HighEntropySections.Add($"{entryPointSection.Name} ({entropy:F2})");
                            score += 25.0f;
                        }
                    }
                }

                if (entryPointSection.RawSize > 0 && entryPointSection.VirtualSize > 0)
                {
                    Single ratio = (Single)entryPointSection.VirtualSize / entryPointSection.RawSize;
                    if (ratio > 5.0f)
                    {
                        indicators.Add($"Entry point section '{entryPointSection.Name}' size anomaly: VSize={entryPointSection.VirtualSize} RSize={entryPointSection.RawSize} Ratio={ratio:F1}");
                        score += 20.0f;
                    }
                }

                Boolean epSectionRwe = (entryPointSection.Characteristics & 0xE0000000) == 0xE0000000;
                if (epSectionRwe)
                {
                    indicators.Add($"Entry point section '{entryPointSection.Name}' has RWE permissions");
                    score += 25.0f;
                }
            }

            Boolean entryPointInText = false;
            foreach (var section in sections)
            {
                if (section.Name == ".text" || section.Name.StartsWith(".text"))
                {
                    UInt32 textStart = section.VirtualAddress;
                    UInt32 textEnd = section.VirtualAddress + section.VirtualSize;
                    if (entryPoint >= textStart && entryPoint < textEnd)
                    {
                        entryPointInText = true;
                        break;
                    }
                }
            }

            if (!entryPointInText && entryPointInLastSection)
            {
                indicators.Add("Entry point is not in .text section but in the last section");
                score += 30.0f;
            }

            result.Entropy = CalculateEntropy(data, 0, data.Length);

            Single threshold = 50.0f;
            Boolean hasMultipleIndicators = indicators.Count >= 2;

            result.IsInfected = score >= threshold && hasMultipleIndicators;
            result.Confidence = Math.Min(score / 100.0f, 1.0f);
            result.Indicators = indicators;

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Single CalculateEntropy(Byte[] data, Int32 offset, Int32 count)
        {
            if (count <= 0 || offset < 0 || offset + count > data.Length)
                return 0.0f;

            Span<UInt64> frequency = stackalloc UInt64[256];
            frequency.Clear();

            for (Int32 i = offset; i < offset + count; i++)
                frequency[data[i]]++;

            Double len = count;
            Double entropy = 0.0;

            for (Int32 i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    Double probability = frequency[i] / len;
                    entropy -= probability * Math.Log2(probability);
                }
            }

            return (Single)entropy;
        }
    }

    public sealed class SectionInfoRaw
    {
        public String Name { get; }
        public UInt32 VirtualSize { get; }
        public UInt32 VirtualAddress { get; }
        public UInt32 RawSize { get; }
        public UInt32 RawAddress { get; }
        public UInt32 Characteristics { get; }
        public Int32 Index { get; set; }

        public SectionInfoRaw(String name, UInt32 virtualSize, UInt32 virtualAddress, UInt32 rawSize, UInt32 rawAddress, UInt32 characteristics, Int32 index)
        {
            Name = name;
            VirtualSize = virtualSize;
            VirtualAddress = virtualAddress;
            RawSize = rawSize;
            RawAddress = rawAddress;
            Characteristics = characteristics;
            Index = index;
        }
    }
}
