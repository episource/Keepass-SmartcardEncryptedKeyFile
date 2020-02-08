using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.Linq.Mapping;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Episource.KeePass.EKF.Util.Windows {
    /// <summary>
    /// Exposes native device events. Refrain from long running or blocking actions within event handlers.
    /// </summary>
    public sealed partial class NativeDeviceEvents : IDisposable {
        
        private readonly Guid UsbClassGuid = new Guid("A5DCBF10-6530-11D2-901F-00C04FB951ED");
       
        private readonly MessagePump receiver;
        private readonly IntPtr notificationHandle;

        public NativeDeviceEvents() {
            this.receiver = new MessagePump(this.HandleMessage);
            this.notificationHandle = RegisterDeviceNotificationImpl(
                this.receiver,Guid.Empty,
                RegisterDeviceNotificationFlags.DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
        }

        public event EventHandler<DeviceEventArgs> AnyDeviceEvent;
        public event EventHandler<InterfaceDeviceEventArgs> AnyInterfaceEvent;
        public event EventHandler<InterfaceDeviceEventArgs> UsbDeviceEvent;

        public void Dispose() {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        private /*protected virtual*/ void Dispose(bool disposing) {

            if (this.receiver.Handle != IntPtr.Zero) {
                UnregisterDeviceNotificationImpl(this.notificationHandle);

                if (disposing) {
                    this.receiver.DestroyHandle();
                }
            }
        }

        private void HandleMessage(Message m) {
            var anyArgs = ReadMessageAsDeviceEventArgs(m);
            if (anyArgs == null) {
                return;
            }
            
            RaiseEvent(this.AnyDeviceEvent, anyArgs);

            var interfaceArgs = anyArgs as InterfaceDeviceEventArgs;
            if (interfaceArgs != null) {
                RaiseEvent(this.AnyInterfaceEvent, interfaceArgs);

                if (interfaceArgs.DeviceClassId == this.UsbClassGuid) {
                    RaiseEvent(this.UsbDeviceEvent, interfaceArgs);
                }
            }
        }

        private void RaiseEvent<T>(EventHandler<T> handler, T args) {
            if (handler != null) {
                handler(this, args);
            }
        }

        ~NativeDeviceEvents() {
            this.Dispose(false);
        }
    }
}