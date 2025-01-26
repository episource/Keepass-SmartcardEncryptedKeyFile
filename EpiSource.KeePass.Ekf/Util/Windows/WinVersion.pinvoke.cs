using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class WinVersion {
        
        /// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_osversioninfoexw
        [StructLayout(LayoutKind.Sequential)]
        private struct OsVersionInfoEx
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public short wServicePackMajor;
            public short wServicePackMinor;
            public short wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }
        
        [DllImport("ntdll.dll", SetLastError = false, ExactSpelling = true)]
        private static extern int RtlGetVersion(ref OsVersionInfoEx lpVersionInformation);
        
    }
}