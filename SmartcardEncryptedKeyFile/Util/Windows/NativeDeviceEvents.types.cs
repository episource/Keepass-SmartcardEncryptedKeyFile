using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Forms;

namespace Episource.KeePass.EKF.Util.Windows {
    // This file contains all nested types that are not exclusive to pinvoke
    public sealed partial class NativeDeviceEvents {
        private sealed class MessagePump : NativeWindow {

            private readonly Action<Message> handler;

            public MessagePump(Action<Message> handler) {
                this.handler = handler;
                this.CreateHandle(new CreateParams() { Caption = this.GetType().FullName});
            }
            
            protected override void WndProc(ref Message m) {
                this.handler(m);
                base.WndProc(ref m);
            }
        }

        // Important: Values must match DEV_BROADCAST_HDR definitions. See https://docs.microsoft.com/de-de/windows/win32/api/dbt/ns-dbt-dev_broadcast_hdr
        public enum DeviceType : int {
            /// <summary>
            ///  Device type not known or not implemented.
            /// </summary>
            Unknown = -1,
            
            /// <summary>
            /// OEM- or IHV-defined device type. See https://docs.microsoft.com/windows/desktop/api/dbt/ns-dbt-dev_broadcast_oem.
            /// </summary>
            // DBT_DEVTYP_OEM
            Oem = 0x00,
            
            /// <summary>
            /// Logical volume. See https://docs.microsoft.com/windows/desktop/api/dbt/ns-dbt-dev_broadcast_volume.
            /// </summary>
            // DBT_DEVTYP_VOLUME
            Volume = 0x02,
            
            /// <summary>
            /// Port device (serial or parallel). See https://docs.microsoft.com/windows/desktop/api/dbt/ns-dbt-dev_broadcast_port_a.
            /// </summary>
            // DBT_DEVTYP_PORT
            Port = 0x03,
            
            /// <summary>
            /// Class of (hardware?) devices. See https://docs.microsoft.com/windows/desktop/api/dbt/ns-dbt-dev_broadcast_deviceinterface_a.
            /// </summary>
            // DBT_DEVTYP_DEVICEINTERFACE
            Interface = 0x05,
            
            /// <summary>
            /// File system handle. See https://docs.microsoft.com/windows/desktop/api/dbt/ns-dbt-dev_broadcast_handle.
            /// </summary>
            // DBT_DEVTYP_HANDLE
            Handle = 0x06
        }

        // https://docs.microsoft.com/en-us/windows/win32/devio/wm-devicechange
        public enum NotificationReason : uint {
            /// <summary>
            /// Notification reason is unknown.
            /// </summary>
            Unknown = 0x0000,
            
            /// <summary>
            ///  A request to change the current configuration (dock or undock) has been canceled.
            /// </summary>
            // DBT_CONFIGCHANGECANCELED
            ConfigChangeCanceled = 0x0019,
            
            /// <summary>
            /// The current configuration has changed, due to a dock or undock.
            /// </summary>
            // DBT_CONFIGCHANGED
            ConfigChanged = 0x0018,
            
            /// <summary>
            /// A custom event has occurred.
            /// </summary>
            // DBT_CUSTOMEVENT
            CustomEvent = 0x8006,
            
            /// <summary>
            /// A device or piece of media has been inserted and is now available.
            /// </summary>
            // DBT_DEVICEARRIVAL
            DeviceArrival = 0x8000,
            
            /// <summary>
            /// Permission is requested to remove a device or piece of media. Any application can deny this request and cancel the removal.
            /// </summary>
            // DBT_DEVICEQUERYREMOVE
            DeviceQueryRemove = 0x8001,
            
            /// <summary>
            /// A request to remove a device or piece of media has been canceled.
            /// </summary>
            // DBT_DEVICEQUERYREMOVEFAILED
            DeviceQueryRemoveFailed = 0x8002,
            
            /// <summary>
            /// A device or piece of media has been removed.
            /// </summary>
            // DBT_DEVICEREMOVECOMPLETE
            DeviceRemoveComplete = 0x8004,
            
            /// <summary>
            /// A device or piece of media is about to be removed. Cannot be denied.
            /// </summary>
            // DBT_DEVICEREMOVEPENDING
            DeviceRemovePending = 0x8003,
            
            /// <summary>
            /// A device-specific event has occurred.
            /// </summary>
            // DBT_DEVICETYPESPECIFIC
            DeviceTypeSpecific = 0x8005,
            
            /// <summary>
            /// A device has been added to or removed from the system.
            /// </summary>
            // DBT_DEVNODES_CHANGED
            DevNodesChanged = 0x0007,
            
            /// <summary>
            /// Permission is requested to change the current configuration (dock or undock).
            /// </summary>
            // DBT_QUERYCHANGECONFIG
            QueryChangeConfig = 0x0017,
            
            /// <summary>
            /// The meaning of this message is user-defined.
            /// </summary>
            // DBT_USERDEFINED
            UserDefined = 0xffff,
        }

        public class DeviceEventArgs : EventArgs {

            public DeviceEventArgs(DeviceType deviceType, NotificationReason reason) {
                this.DeviceType = deviceType;
                this.Reason = reason;
            }
            public DeviceType DeviceType { get; private set; }
            public NotificationReason Reason { get; private set; }

            public override string ToString() {
                return string.Format("{0}[{1}]", this.GetType().Name, this.FormatDataAsString());
            }

            protected virtual string FormatDataAsString() {
                return string.Format("DeviceType: {0}; Reason: {1}", DeviceType, Reason);
            }
        }
        
        public sealed class InterfaceDeviceEventArgs : DeviceEventArgs {
            public const DeviceType KnownDeviceType = DeviceType.Interface;  
            
            public InterfaceDeviceEventArgs(NotificationReason reason, Guid deviceClass, string deviceName) 
                : base(KnownDeviceType, reason) {
                this.DeviceClassId = deviceClass;
                this.DeviceName = deviceName;
            }
            
            public Guid DeviceClassId { get; private set; }
            public string DeviceName { get; private set; }

            private string friendlyName = null;
            public string FriendlyName {
                get {
                    if (this.friendlyName == null) {
                        try {
                            this.friendlyName = NativeDevice.TranslateDbccNameToFriendlyName(this.DeviceName);
                        }
                        catch (Win32Exception e) {
                            Debugger.Log(0, "exception", "Failed to retrieve friendly name of device `" + this.DeviceName + "`: " + e);
                            return null;
                        }
                    }

                    return this.friendlyName;
                }
            }

            protected override string FormatDataAsString() {
                return string.Format("{0}; DeviceClassId: {1}; DeviceName: {2}; FriendlyName: {3}",
                    base.FormatDataAsString(), this.DeviceClassId, this.DeviceName, this.FriendlyName);
            }
        }

    }
}