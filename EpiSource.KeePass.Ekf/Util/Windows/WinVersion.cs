using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    /// <summary>
    /// Retrieves windows version information, independent of manifest configuration and compatibility settings.
    /// See also:
    ///  - https://stackoverflow.com/questions/32625934/how-can-i-detect-which-version-of-windows-is-running/48119148#48119148
    ///  - https://stackoverflow.com/questions/69038560/detect-windows-11-with-net-framework-or-windows-api
    /// </summary>
    public static partial class WinVersion {

        private static readonly Lazy<OsVersionInfo> osVersionInfo = new Lazy<OsVersionInfo>(() => {
            var info = new OsVersionInfoEx() {
                dwOSVersionInfoSize = Marshal.SizeOf(typeof(OsVersionInfoEx))
            };

            var result = RtlGetVersion(ref info);
            if (result != 0) {
                throw new Win32Exception("RtlGetVersion failed");
            }
            return new OsVersionInfo(info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber, info.dwPlatformId, info.szCSDVersion, info.wServicePackMajor, info.wServicePackMinor);
        });

        public static OsVersionInfo OSVersion {
            get {
                return osVersionInfo.Value;
            }
        }

        public static bool IsWin10 {
            get {
                return OSVersion.MajorVersion == 10 && OSVersion.MinorVersion == 0 && OSVersion.BuildNumber < 22000;
            }
        }

        public static bool IsWin11 {
            get {
                return OSVersion.MajorVersion == 10 && OSVersion.MinorVersion == 0 && OSVersion.BuildNumber >= 22000;
            }
        }

    }
}