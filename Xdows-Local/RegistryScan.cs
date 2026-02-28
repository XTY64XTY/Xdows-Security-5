namespace Xdows_Local
{
    public class RegistryScan
    {
        public string Scan(string key)
        {
            return Native_RegistryScanner.ScanManaged(key);
        }
    }
}
