using Helper;
using Protection;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

if (Marshal.SizeOf<BootFilterRegisterResponse>() != 32 ||
    Marshal.SizeOf<BootFilterConfigureRequest>() != 144 ||
    Marshal.SizeOf<BootFilterWriteEvent>() != 40 ||
    Marshal.SizeOf<BootFilterDecision>() != 24 ||
    Marshal.SizeOf<BootFilterState>() != 56)
{
    throw new InvalidOperationException("Boot filter managed protocol structure sizes do not match the native ABI.");
}

if (Crc32.Compute(Encoding.ASCII.GetBytes("123456789")) != 0xCBF43926u)
    throw new InvalidOperationException("GPT CRC32 implementation failed the standard test vector.");

var snapshot = new BootProtectionSnapshot(
    0,
    "Synthetic disk",
    "SERIAL-TEST",
    1024 * 1024,
    PhysicalDiskPartitionStyle.Gpt,
    512,
    [new BootRawRegion("MBR", 0, [0x4D, 0x5A, 0x55, 0xAA])],
    [@"X:\|EFI\Microsoft\Boot"],
    [
        new BootFileEntry(
            @"X:\",
            @"EFI\Microsoft\Boot\bootmgfw.efi",
            [1, 2, 3, 4, 5],
            FileAttributes.System,
            DateTime.UnixEpoch)
    ]);

String temporaryRoot = Path.Combine(
    Path.GetTempPath(),
    $"Xdows-R3BootStore-{Guid.NewGuid():N}");

try
{
    var store = new BootBaselineStore(temporaryRoot);
    store.Save(snapshot);
    if (!store.TryLoad(out BootProtectionSnapshot? loaded) || loaded is null)
        throw new InvalidOperationException("Synthetic boot baseline did not round-trip.");

    if (loaded.DiskSerialNumber != snapshot.DiskSerialNumber ||
        loaded.RawRegions.Count != 1 ||
        loaded.Files.Count != 1 ||
        !CryptographicOperations.FixedTimeEquals(
            loaded.Files[0].Data,
            snapshot.Files[0].Data))
    {
        throw new InvalidOperationException("Synthetic boot baseline changed during round-trip.");
    }

    String archivePath = Path.Combine(temporaryRoot, "boot-baseline.zip");
    Byte[] archive = File.ReadAllBytes(archivePath);
    Int32 tamperOffset = Math.Max(0, archive.Length - 24);
    archive[tamperOffset] ^= 0x5A;
    File.WriteAllBytes(archivePath, archive);
    if (store.TryLoad(out _))
        throw new InvalidOperationException("Tampered boot baseline was accepted.");

    Console.WriteLine("R3 boot baseline store runtime tests passed.");
}
finally
{
    if (Directory.Exists(temporaryRoot))
        Directory.Delete(temporaryRoot, recursive: true);
}
