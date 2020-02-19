namespace Episource.KeePass.EKF.Util.Windows {
    public static partial class NativeDevice {
        public static string TranslateDbccNameToFriendlyName(string dbccName) {
            using (var devInfoSet = SetupDiCreateDeviceInfoListUnboundImpl()) {
                using (var _ = SetupDiOpenDeviceInterfaceByNameImpl(devInfoSet, dbccName)) {
                    // note: iteration could most probably be omitted, as there should be precisely one element
                    for (uint i = 0; i < uint.MaxValue; ++i) {
                        BoundDeviceInfoHandle enumDeviceHandle;
                        if (!SetupDiEnumDeviceInfoImpl(devInfoSet, i, out enumDeviceHandle)) {
                            return null;
                        }

                        string friendlyName = SetupDiGetDeviceRegistryPropertyStringImpl(devInfoSet, enumDeviceHandle,
                            DeviceRegistryProperty.SPDRP_FRIENDLYNAME);
                        if (!string.IsNullOrWhiteSpace(friendlyName)) {
                            return friendlyName;
                        }

                        friendlyName = SetupDiGetDeviceRegistryPropertyStringImpl(devInfoSet, enumDeviceHandle,
                            DeviceRegistryProperty.SPDRP_DEVICEDESC);
                        if (!string.IsNullOrWhiteSpace(friendlyName)) {
                            return friendlyName;
                        }
                    }

                    return null;
                }
            }
        }
    }
}