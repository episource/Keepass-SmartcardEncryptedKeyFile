namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class WinVersion {
        public sealed class OsVersionInfo {
            private readonly int majorVersion, minorVersion, buildNumber, platformId, servicePackMajorVersion, servicePackMinorVersion;
            private readonly string servicePackDescription;

            public OsVersionInfo(int majorVersion, int minorVersion, int buildNumber, int platformId, string servicePackDescription, int servicePackMajorVersion, int servicePackMinorVersion) {
                this.majorVersion = majorVersion;
                this.minorVersion = minorVersion;
                this.buildNumber = buildNumber;
                this.platformId = platformId;
                this.servicePackMajorVersion = servicePackMajorVersion;
                this.servicePackMinorVersion = servicePackMinorVersion;
                this.servicePackDescription = servicePackDescription;
            }

            public int MajorVersion {
                get {
                    return this.majorVersion;
                }
            }
            public int MinorVersion {
                get {
                    return this.minorVersion;
                }
            }
            public int BuildNumber {
                get {
                    return this.buildNumber;
                }
            }
            public int PlatformId {
                get {
                    return this.platformId;
                }
            }
            public int ServicePackMajorVersion {
                get {
                    return this.servicePackMajorVersion;
                }
            }
            public int ServicePackMinorVersion {
                get {
                    return this.servicePackMinorVersion;
                }
            }
            public string ServicePackDescription {
                get {
                    return this.servicePackDescription;
                }
            }
        }
    }
}