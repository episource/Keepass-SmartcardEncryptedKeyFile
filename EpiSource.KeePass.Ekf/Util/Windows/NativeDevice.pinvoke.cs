using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

using Microsoft.Win32.SafeHandles;

// ReSharper disable InconsistentNaming
// ReSharper disable IdentifierTypo
// ReSharper disable MemberCanBePrivate.Local
// ReSharper disable UnusedMember.Local

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeDevice {
        [Flags]
        // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/nf-setupapi-setupdiopendeviceinterfacea
        private enum OpenDeviceInterfaceFlags : uint {
            // ReSharper disable once InconsistentNaming
            NONE = 0x0,

            // ReSharper disable once InconsistentNaming
            DIODI_NO_ADD = 0x1
        }

        // windows sdk headers or reactos repo (https://github.com/reactos/reactos/blob/master/sdk/tools/mkhive/registry.h)
        private enum RegDataType : uint {
            REG_NONE = 0,
            REG_SZ = 1,
            REG_BINARY = 3,
            REG_DWORD = 4,
            REG_DWORD_LITTLE_ENDIAN = 4,
            REG_DWORD_BIG_ENDIAN = 5,
            REG_LINK = 6,
            REG_MULTI_SZ = 7,
            REG_RESOURCE_LIST = 8,
            REG_FULL_RESOURCE_DESCRIPTOR = 9,
            REG_RESOURCE_REQUIREMENTS_LIST = 10,
            REQ_QWORD = 11,
            REQ_QWORD_LITTLE_ENDIAN = 11
        }

        // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya
        // SetupAPI.h from windows sdk
        private enum DeviceRegistryProperty : uint {
            /// <summary>
            /// The function retrieves the device's address.
            /// </summary>
            SPDRP_ADDRESS = 0x0000001C,
            
            /// <summary>
            /// The function retrieves the device's bus number.
            /// </summary>
            SPDRP_BUSNUMBER = 0x00000015,
            
            /// <summary>
            /// The function retrieves the GUID for the device's bus type.
            /// </summary>
            SPDRP_BUSTYPEGUID = 0x00000013,
            
            /// <summary>
            /// The function retrieves a bitwise OR of the following CM_DEVCAP_Xxx flags in a DWORD. The device capabilities that are represented by these flags correspond to the device capabilities that are represented by the members of the DEVICE_CAPABILITIES structure. The CM_DEVCAP_Xxx constants are defined in Cfgmgr32.h.
            /// </summary>
            SPDRP_CAPABILITIES = 0x0000000F,
            
            /// <summary>
            /// The function retrieves a bitwise OR of a device's characteristics flags in a DWORD. For a description of these flags, which are defined in Wdm.h and Ntddk.h, see the DeviceCharacteristics parameter of the IoCreateDevice function.
            /// </summary>
            SPDRP_CHARACTERISTICS = 0x0000001B,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the device setup class of a device.
            /// </summary>
            SPDRP_CLASS = 0x00000007,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the GUID that represents the device setup class of a device.
            /// </summary>
            SPDRP_CLASSGUID = 0x00000008,
            
            /// <summary>
            /// The function retrieves a REG_MULTI_SZ string that contains the list of compatible IDs for a device. For information about compatible IDs, see Device Identification Strings.
            /// </summary>
            SPDRP_COMPATIBLEIDS = 0x00000002,
            
            /// <summary>
            /// The function retrieves a bitwise OR of a device's configuration flags in a DWORD value. The configuration flags are represented by the CONFIGFLAG_Xxx bitmasks that are defined in Regstr.h.
            /// </summary>
            SPDRP_CONFIGFLAGS = 0x0000000A,
            
            /// <summary>
            /// (Windows XP and later) The function retrieves a CM_POWER_DATA structure that contains the device's power management information.
            /// </summary>
            SPDRP_DEVICE_POWER_DATA = 0x0000001E,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the description of a device.
            /// </summary>
            SPDRP_DEVICEDESC = 0x00000000,
            
            /// <summary>
            /// The function retrieves a DWORD value that represents the device's type. For more information, see Specifying Device Types.
            /// </summary>
            SPDRP_DEVTYPE = 0x00000019,
            
            /// <summary>
            /// The function retrieves a string that identifies the device's software key (sometimes called the driver key). For more information about driver keys, see Registry Trees and Keys for Devices and Drivers.
            /// </summary>
            SPDRP_DRIVER = 0x00000009,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the name of the device's enumerator.
            /// </summary>
            SPDRP_ENUMERATOR_NAME = 0x00000016,
            
            /// <summary>
            /// The function retrieves a DWORD value that indicates whether a user can obtain exclusive use of the device. The returned value is one if exclusive use is allowed, or zero otherwise. For more information, see IoCreateDevice.
            /// </summary>
            SPDRP_EXCLUSIVE = 0x0000001A,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the friendly name of a device.
            /// </summary>
            SPDRP_FRIENDLYNAME = 0x0000000C,
            
            /// <summary>
            /// The function retrieves a REG_MULTI_SZ string that contains the list of hardware IDs for a device. For information about hardware IDs, see Device Identification Strings.
            /// </summary>
            SPDRP_HARDWAREID = 0x00000001,
            
            /// <summary>
            /// (Windows XP and later) The function retrieves a DWORD value that indicates the installation state of a device. The installation state is represented by one of the CM_INSTALL_STATE_Xxx values that are defined in Cfgmgr32.h. The CM_INSTALL_STATE_Xxx values correspond to the DEVICE_INSTALL_STATE enumeration values.
            /// </summary>
            SPDRP_INSTALL_STATE = 0x00000022,
            
            /// <summary>
            /// The function retrieves the device's legacy bus type as an INTERFACE_TYPE value (defined in Wdm.h and Ntddk.h).
            /// </summary>
            SPDRP_LEGACYBUSTYPE = 0x00000014,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the hardware location of a device.
            /// </summary>
            SPDRP_LOCATION_INFORMATION = 0x0000000D,
            
            /// <summary>
            /// (Windows Server 2003 and later) The function retrieves a REG_MULTI_SZ string that represents the location of the device in the device tree.
            /// </summary>
            SPDRP_LOCATION_PATHS = 0x00000023,
            
            /// <summary>
            /// The function retrieves a REG_MULTI_SZ string that contains the names of a device's lower-filter drivers.
            /// </summary>
            SPDRP_LOWERFILTERS = 0x00000012,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the name of the device manufacturer.
            /// </summary>
            SPDRP_MFG = 0x0000000B,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the name that is associated with the device's PDO. For more information, see IoCreateDevice.
            /// </summary>
            SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E,
            
            /// <summary>
            /// (Windows XP and later) The function retrieves the device's current removal policy as a DWORD that contains one of the CM_REMOVAL_POLICY_Xxx values that are defined in Cfgmgr32.h.
            /// </summary>
            SPDRP_REMOVAL_POLICY = 0x0000001F,
            
            /// <summary>
            /// (Windows XP and later) The function retrieves the device's hardware-specified default removal policy as a DWORD that contains one of the CM_REMOVAL_POLICY_Xxx values that are defined in Cfgmgr32.h.
            /// </summary>
            SPDRP_REMOVAL_POLICY_HW_DEFAULT = 0x00000020,
            
            /// <summary>
            /// (Windows XP and later) The function retrieves the device's override removal policy (if it exists) from the registry, as a DWORD that contains one of the CM_REMOVAL_POLICY_Xxx values that are defined in Cfgmgr32.h.
            /// </summary>
            SPDRP_REMOVAL_POLICY_OVERRIDE = 0x00000021,
            
            /// <summary>
            /// The function retrieves a SECURITY_DESCRIPTOR structure for a device.
            /// </summary>
            SPDRP_SECURITY = 0x00000017,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the device's security descriptor. For information about security descriptor strings, see Security Descriptor Definition Language (Windows). For information about the format of security descriptor strings, see Security Descriptor Definition Language (Windows).
            /// </summary>
            SPDRP_SECURITY_SDS = 0x00000018,
            
            /// <summary>
            /// The function retrieves a REG_SZ string that contains the service name for a device.
            /// </summary>
            SPDRP_SERVICE = 0x00000004,
            
            /// <summary>
            /// The function retrieves a DWORD value set to the value of the UINumber member of the device's DEVICE_CAPABILITIES structure.
            /// </summary>
            SPDRP_UI_NUMBER = 0x00000010,
            
            /// <summary>
            /// The function retrieves a format string (REG_SZ) used to display the UINumber value.
            /// </summary>
            SPDRP_UI_NUMBER_DESC_FORMAT = 0X0000001D,
            
            /// <summary>
            /// The function retrieves a REG_MULTI_SZ string that contains the names of a device's upper filter drivers.
            /// </summary>
            SPDRP_UPPERFILTERS = 0x00000011,
        }
        
        // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/ns-setupapi-sp_devinfo_data
        // ReSharper disable once IdentifierTypo
        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA {
            public static readonly SP_DEVINFO_DATA DEFAULT = new SP_DEVINFO_DATA()
                {cbSize = (uint) Marshal.SizeOf<SP_DEVINFO_DATA>()};

            private uint cbSize;
            public Guid ClassGuid;
            private uint DevInst;
            private uint Reserved;
        }

        private sealed class DeviceInfoListHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public DeviceInfoListHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                return NativeDevicePinvoke.SetupDiDestroyDeviceInfoList(this.handle);
            }
        }

        private sealed class BoundDeviceInfoHandle : SafeHandleZeroOrMinusOneIsInvalid {
            private readonly SP_DEVINFO_DATA handleData = SP_DEVINFO_DATA.DEFAULT;
            private readonly DeviceInfoListHandle listHandle;
            private GCHandle pinnedGcHandle;
            private bool isPinned;

            public BoundDeviceInfoHandle(DeviceInfoListHandle listHandle) : base(true) {
                this.listHandle = listHandle;
                
                this.pinnedGcHandle = GCHandle.Alloc(this.handleData, GCHandleType.Pinned);
                this.isPinned = true;
                this.SetHandle(this.pinnedGcHandle.AddrOfPinnedObject());
            }
            
            protected override bool ReleaseHandle() {
                if (this.IsClosed || this.IsInvalid) {
                    return true;
                }
                
                return NativeDevicePinvoke.SetupDiDeleteDeviceInterfaceData(this.listHandle, this.handle);
            }

            protected override void Dispose(bool disposing) {
                base.Dispose(disposing);

                if (this.isPinned) {
                    this.pinnedGcHandle.Free();
                    this.isPinned = false;
                }
            }
        }

        private static class NativeDevicePinvoke {
            // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/nf-setupapi-setupdicreatedeviceinfolist
            [DllImport("Setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern DeviceInfoListHandle SetupDiCreateDeviceInfoList(IntPtr classGuid, IntPtr hwndParent);

            // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/nf-setupapi-setupdidestroydeviceinfolist
            [DllImport("Setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

            // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/nf-setupapi-setupdiopendeviceinterfacew
            [DllImport("Setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool SetupDiOpenDeviceInterface(DeviceInfoListHandle deviceInfoSet,
                [MarshalAs(UnmanagedType.LPTStr)] string devicePath, OpenDeviceInterfaceFlags openFlags,
                BoundDeviceInfoHandle deviceInfoHandle);
            
            // https://docs.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdideletedeviceinterfacedata
            [DllImport("Setupapi.dll", CharSet =  CharSet.Auto, SetLastError = true)]
            public static extern bool SetupDiDeleteDeviceInterfaceData(DeviceInfoListHandle deviceInfoSet,
                IntPtr deviceInterfaceData);

            // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/nf-setupapi-setupdienumdeviceinfo
            [DllImport("Setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool SetupDiEnumDeviceInfo(DeviceInfoListHandle deviceInfoSet, uint memberIndex,
                BoundDeviceInfoHandle deviceInfoHandle);

            // https://docs.microsoft.com/de-de/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceregistrypropertya
            [DllImport("Setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool SetupDiGetDeviceRegistryProperty(DeviceInfoListHandle deviceInfoSet,
                BoundDeviceInfoHandle deviceInfoHandle, DeviceRegistryProperty property, out uint propertyRegDataType,
                byte[] propertyBuffer, uint propertyBufferSize, out uint requiredSize);
        }

        private static DeviceInfoListHandle SetupDiCreateDeviceInfoListUnboundImpl() {
            return PinvokeUtil.DoPinvokeWithException(
                () => NativeDevicePinvoke.SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero),
                x => !x.Result.IsInvalid);
        }

        // fills device info list with requested information
        private static BoundDeviceInfoHandle SetupDiOpenDeviceInterfaceByNameImpl(DeviceInfoListHandle deviceInfoSet, string dbccName) {
            var deviceInfoHandle = new BoundDeviceInfoHandle(deviceInfoSet);
            try {
                PinvokeUtil.DoPinvokeWithException(
                    // ReSharper disable once AccessToDisposedClosure
                    () => NativeDevicePinvoke.SetupDiOpenDeviceInterface(deviceInfoSet, dbccName,
                        OpenDeviceInterfaceFlags.NONE, deviceInfoHandle));
            }
            catch (Win32Exception) {
                deviceInfoHandle.SetHandleAsInvalid();
                deviceInfoHandle.Dispose();
                throw;
            }

            return deviceInfoHandle;
        }

        private static bool SetupDiEnumDeviceInfoImpl(DeviceInfoListHandle deviceInfoSet, uint memberIndex,
            out BoundDeviceInfoHandle deviceInfoHandle) {
            // https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
            const int ERROR_NO_MORE_ITEMS = 259;
        
            var boundHandle = new BoundDeviceInfoHandle(deviceInfoSet);
            try {
                // ReSharper disable once AccessToDisposedClosure
                var success = PinvokeUtil.DoPinvokeWithException(
                    () => NativeDevicePinvoke.SetupDiEnumDeviceInfo(deviceInfoSet, memberIndex, boundHandle),
                    res => res.Result || res.Win32ErrorCode == ERROR_NO_MORE_ITEMS);
                
                if (success) {
                    deviceInfoHandle = boundHandle;
                    return true;
                }
            }
            catch (Win32Exception) {
                boundHandle.SetHandleAsInvalid();
                boundHandle.Dispose();
                deviceInfoHandle = null;
                throw;
            }
            
            boundHandle.SetHandleAsInvalid();
            boundHandle.Dispose();
            deviceInfoHandle = null;
            return false;
        }

        private static string SetupDiGetDeviceRegistryPropertyStringImpl(DeviceInfoListHandle deviceInfoSet,
            BoundDeviceInfoHandle deviceInfoHandle, DeviceRegistryProperty property) {
            //https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
            const int ERROR_INVALID_DATA = 13;
            const int ERROR_INSUFFICIENT_BUFFER = 122;

            uint dataType = 0;
            uint requiredSize = 0;
            var result = PinvokeUtil.DoPinvokeWithException(() => NativeDevicePinvoke.SetupDiGetDeviceRegistryProperty(
                deviceInfoSet, deviceInfoHandle, property, out dataType, null, 0, out requiredSize),
                res => res.Result || res.Win32ErrorCode == ERROR_INVALID_DATA || res.Win32ErrorCode == ERROR_INSUFFICIENT_BUFFER);
            if (!result && Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER) {
                return null;
            }
            if (dataType != (uint)RegDataType.REG_SZ) {
                throw new ArgumentException("Not a string property: " + property, "property");
            }

            var nameBuffer = new byte[requiredSize];
            result = PinvokeUtil.DoPinvokeWithException(() =>
                NativeDevicePinvoke.SetupDiGetDeviceRegistryProperty(deviceInfoSet, deviceInfoHandle, property,
                    out dataType, nameBuffer, requiredSize, out requiredSize),
                    res => res.Result || res.Win32ErrorCode == ERROR_INVALID_DATA);
            if (!result) {
                return null;
            }

            return Marshal.SystemDefaultCharSize == 2 
                ? Encoding.Unicode.GetString(nameBuffer).TrimEnd('\0') 
                : Encoding.ASCII.GetString(nameBuffer).TrimEnd('\0');
        } 
    }
}