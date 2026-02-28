namespace Helper
{
    public static class DiskOperator
    {
        public static byte[] ReadBootSector(int physicalDriveIndex)
        {
            return Native_DiskOperator.ReadBootSectorManaged(physicalDriveIndex) ?? [];
        }

        public static byte[] ReadVolumeBootRecord(string driveLetter)
        {
            return Native_DiskOperator.ReadVolumeBootRecordManaged(driveLetter) ?? [];
        }
    }
}
