using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Windows.Forms;

// ReSharper disable UnusedMember.Local
// ReSharper disable MemberCanBePrivate.Local

namespace EpiSource.KeePass.Ekf.Util.Windows {
    // this file contains all functionality and types specific to pinvoke
    public sealed partial class NativeDeviceEvents {
        // https://docs.microsoft.com/de-de/windows/win32/api/dbt/ns-dbt-dev_broadcast_hdr
        // ReSharper disable once InconsistentNaming
        // ReSharper disable once IdentifierTypo
        [StructLayout(LayoutKind.Sequential)]
        private struct DEV_BROADCAST_HDR {
            public uint dbcc_size;
            public uint dbcc_devicetype;
            public uint dbcc_reserved;
        }
        
        // https://docs.microsoft.com/de-de/windows/win32/api/dbt/ns-dbt-dev_broadcast_deviceinterface_a
        // forces name to be empty when marshalling .net->native
        // retrieves only first char when marshalling native->.net
        [StructLayout(LayoutKind.Sequential)]
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        [SuppressMessage("ReSharper", "IdentifierTypo")]
        [SuppressMessage("ReSharper", "PrivateFieldCanBeConvertedToLocalVariable")]
        private struct DEV_BROADCAST_DEVICEINTERFACE_NO_NAME {
            // ReSharper disable once IdentifierTypo
            public DEV_BROADCAST_DEVICEINTERFACE_NO_NAME(Guid classGuid) {
                this.dbcc_size = (uint)Marshal.SizeOf<DEV_BROADCAST_DEVICEINTERFACE_NO_NAME>();
                this.dbcc_devicetype = (uint)DeviceType.Interface;
                this.dbcc_reserved = 0;
                this.dbcc_classguid = classGuid;
                this.dbcc_name = 0;
            }

            public readonly uint dbcc_size;
            public readonly uint dbcc_devicetype;
            public readonly uint dbcc_reserved;
            public readonly Guid dbcc_classguid;
            private readonly short dbcc_name;
        }

        // https://docs.microsoft.com/de-de/windows/win32/api/winuser/nf-winuser-registerdevicenotificationa?redirectedfrom=MSDN
        [Flags]
        private enum RegisterDeviceNotificationFlags : uint {
            // ReSharper disable once InconsistentNaming
            // ReSharper disable once IdentifierTypo
            NONE = 0x0000,
            
            // ReSharper disable once InconsistentNaming
            // ReSharper disable once IdentifierTypo
            DEVICE_NOTIFY_ALL_INTERFACE_CLASSES = 0x0004
        }
        
        private static class NativeDeviceEventsPinvoke {
            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr RegisterDeviceNotification(IntPtr recipient,
                IntPtr notificationFilter, RegisterDeviceNotificationFlags flags);

            [DllImport("user32.dll", SetLastError = true)]
            public static extern bool UnregisterDeviceNotification(IntPtr handle);
        }

        private static IntPtr RegisterDeviceNotificationImpl(IWin32Window receiver, Guid deviceTypeFilter,
            RegisterDeviceNotificationFlags flags) {
            // ReSharper disable once HeapView.BoxingAllocation
            var filterStructGcHandle = GCHandle.Alloc(new DEV_BROADCAST_DEVICEINTERFACE_NO_NAME(deviceTypeFilter), GCHandleType.Pinned);

            try {
                return PinvokeUtil.DoPinvokeWithException(
                    () => NativeDeviceEventsPinvoke.RegisterDeviceNotification(receiver.Handle,
                        filterStructGcHandle.AddrOfPinnedObject(), flags),
                    r => r != IntPtr.Zero);
            }
            finally {
                filterStructGcHandle.Free();
            }
        }

        private static void UnregisterDeviceNotificationImpl(IntPtr notificationHandle) {
            PinvokeUtil.DoPinvokeWithException(
                () => NativeDeviceEventsPinvoke.UnregisterDeviceNotification(notificationHandle), r => r);
        }

        private static DeviceEventArgs ReadMessageAsDeviceEventArgs(Message m) {
            // ReSharper disable once InconsistentNaming
            const int WM_DEVICECHANGE = 0x0219;
            if (m.Msg != WM_DEVICECHANGE) {
                return null;
            }

            if (m.LParam == IntPtr.Zero) {
                return new DeviceEventArgs(DeviceType.Unknown, NotificationReason.Unknown);
            }
            
            var header = Marshal.PtrToStructure<DEV_BROADCAST_HDR>(m.LParam);
            var deviceType = ConvertEnum(header.dbcc_devicetype, x => (DeviceType)x, DeviceType.Unknown);
            var reason = ConvertEnum(m.WParam, x => (NotificationReason)x, NotificationReason.Unknown);

            switch (deviceType) {
                case DeviceType.Interface:
                    return ExtractInterfaceDeviceEventArgs(header, reason, m.LParam);
                default:
                    return new DeviceEventArgs(deviceType, reason);
            }
        }

        // ReSharper disable once UnusedParameter.Local
        private static InterfaceDeviceEventArgs ExtractInterfaceDeviceEventArgs(
            DEV_BROADCAST_HDR header, NotificationReason reason, IntPtr lParam) {
            var interfaceDeviceInfo = Marshal.PtrToStructure<DEV_BROADCAST_DEVICEINTERFACE_NO_NAME>(lParam);

            var nameOffset = Marshal.OffsetOf<DEV_BROADCAST_DEVICEINTERFACE_NO_NAME>("dbcc_name");
            string name = Marshal.PtrToStringAuto(lParam + nameOffset.ToInt32());
            
            return new InterfaceDeviceEventArgs(reason, interfaceDeviceInfo.dbcc_classguid, name);
        }

        private static TEnum ConvertEnum<TEnum, TVal>(TVal numeric, Func<TVal, TEnum> cast, TEnum defaultValue) where TEnum : struct, IComparable where TVal : struct {
            try {
                return cast(numeric);
            }
            catch (InvalidCastException) {
                return defaultValue;
            }
        }
    }
}