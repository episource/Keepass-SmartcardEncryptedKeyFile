using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming

namespace EpiSource.KeePass.Ekf.UI.Windows {
    public sealed class NativeWinEvents : IDisposable {
        /// <summary>
        /// Subset of: https://docs.microsoft.com/de-de/windows/desktop/WinAuto/event-constants
        /// </summary>
        private enum WinEvents : uint {
            EVENT_SYSTEM_FOREGROUND = 0x0003,
            EVENT_OBJECT_SHOW = 0x8002
        }

        private struct EventHandlerRef {
            // ReSharper disable once UnusedAutoPropertyAccessor.Local
            public WinEventDelegate ManagedHandler { get; set; }
            public IntPtr Handle { get; set; }
        }

        public sealed class WinEventArgs : EventArgs {
            public WinEventArgs(IntPtr eventSource, uint dwmsEventTime) {
                this.EventSource = eventSource;
                var utcNow = DateTimeOffset.UtcNow;
                var ticksNow = (long)unchecked((uint)Environment.TickCount);
                
                var eventTimeLong = (long) dwmsEventTime;
                var eventOffsetMs = eventTimeLong - ticksNow;

                // ticksNow overflowed before eventTime
                if (eventTimeLong < int.MaxValue && ticksNow < int.MaxValue) {
                    eventOffsetMs -= uint.MaxValue - 1;
                }
                
                this.EventTime = DateTimeOffset.UtcNow.AddMilliseconds(eventOffsetMs);
            }

            /// <summary>
            /// Handle to the window that generates the event, or NULL if no window is associated with the event. For example, the mouse pointer is not associated with a window.
            /// </summary>
            public IntPtr EventSource { get; private set; }

            public DateTimeOffset EventTime { get; private set; }
        }

        private readonly Process processToObserve;

        public NativeWinEvents()  { }

        public NativeWinEvents(Process processToObserve) {
            if (processToObserve == null) {
                throw new ArgumentNullException("processToObserve");
            }
            this.processToObserve = processToObserve;
        }

        private readonly IDictionary<EventHandler<WinEventArgs>, EventHandlerRef> foregroundChangedRegistrations =
            new Dictionary<EventHandler<WinEventArgs>, EventHandlerRef>();

        public event EventHandler<WinEventArgs> ForegroundChanged {
            add {
                this.addHandler(this.foregroundChangedRegistrations, value, WinEvents.EVENT_SYSTEM_FOREGROUND);
            }
            remove {
                this.removeHandler(this.foregroundChangedRegistrations, value);
            }
        }
        
        private readonly IDictionary<EventHandler<WinEventArgs>, EventHandlerRef> objectShownRegistrations =
            new Dictionary<EventHandler<WinEventArgs>, EventHandlerRef>();

        public event EventHandler<WinEventArgs> ObjectShown {
            add {
                this.addHandler(this.objectShownRegistrations, value, WinEvents.EVENT_OBJECT_SHOW);
            }
            remove {
                this.removeHandler(this.objectShownRegistrations, value);
            }
        }

        private void addHandler(
            IDictionary<EventHandler<WinEventArgs>, EventHandlerRef> registrations, EventHandler<WinEventArgs> handler,
            WinEvents eventSelection
        ) {
            lock (registrations) {
                if (registrations.ContainsKey(handler)) {
                    return;
                }

                WinEventDelegate internalHandler = (
                    hook, type, hwnd, idObject, idChild, idEventThread, dwmsEventTime
                ) => {
                    WinEventArgs args = new WinEventArgs(hwnd, dwmsEventTime);
                    handler(this, args);
                };

                var handle = this.SetWinEventHook(eventSelection, internalHandler);
                if (handle == IntPtr.Zero) {
                    throw new Win32Exception("Failed to setup native win event.");
                }
                    
                registrations.Add(handler, new EventHandlerRef { Handle = handle, ManagedHandler = internalHandler});
            }
        }

        // ReSharper disable once MemberCanBeMadeStatic.Local
        private void removeHandler(
            IDictionary<EventHandler<WinEventArgs>, EventHandlerRef> registrations, EventHandler<WinEventArgs> handler
        ) {
            lock (registrations) {
                var handlerRef = default(EventHandlerRef);
                if (registrations.TryGetValue(handler, out handlerRef)) {
                    if (!UnhookWinEvent(handlerRef.Handle)) {
                        throw new Win32Exception("Failed to unhook native win event.");
                    }
                    registrations.Remove(handler);
                }
            }
        }
        
        private delegate void WinEventDelegate(
            IntPtr hWinEventHook, uint eventType,
            IntPtr hwnd, int idObject, int idChild, uint dwEventThread, uint dwmsEventTime
        );

        [DllImport("user32.dll")]
        private static extern IntPtr SetWinEventHook(
            uint eventMin, uint eventMax, IntPtr hmodWinEventProc, WinEventDelegate lpfnWinEventProc, uint idProcess,
            uint idThread, uint dwFlags
        );

        private IntPtr SetWinEventHook(WinEvents eventSelection, WinEventDelegate callback) {
            uint pId = 0;
            if (this.processToObserve != null) {
                try {
                    pId = (uint) this.processToObserve.Id;
                } catch (InvalidOperationException) {
                    throw new InvalidOperationException("The process to observe has no process id. Not yet started?");
                }
            }

            const uint anyThreadId = 0;
            const uint outOfContextFlag = 0x0;
            var outOfContextModuleHandle = IntPtr.Zero;

            return SetWinEventHook((uint) eventSelection, (uint) eventSelection, outOfContextModuleHandle, callback,
                pId, anyThreadId,
                outOfContextFlag);
        }

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWinEvent(IntPtr hWinEventHook);

        public void Dispose() {
            lock (this.objectShownRegistrations) {
                lock (this.foregroundChangedRegistrations) {
                    this.Dispose(true);
                    GC.SuppressFinalize(this);
                }
            }
        }

        // ReSharper disable once ParameterOnlyUsedForPreconditionCheck.Local
        private /*protected virtual*/ void Dispose(bool disposing) {
            var exceptions = new LinkedList<Win32Exception>();
            
            // callee either acquires lock or ensures non-concurrent access (finalizer)
            
            foreach (var handlerRef in this.objectShownRegistrations.Values) {
                if (!UnhookWinEvent(handlerRef.Handle)) {
                    exceptions.AddLast(new Win32Exception(Marshal.GetLastWin32Error()));
                }
            }
            this.objectShownRegistrations.Clear();
            
            foreach (var handlerRef in this.foregroundChangedRegistrations.Values) {
                if (!UnhookWinEvent(handlerRef.Handle)) {
                    exceptions.AddLast(new Win32Exception(Marshal.GetLastWin32Error()));
                }
            }
            this.foregroundChangedRegistrations.Clear();

            if (disposing && exceptions.Count > 0) {
                throw new AggregateException("Failed to unhook native window event.", exceptions);
            }
        }

        ~NativeWinEvents() {
            this.Dispose(false);
        }
    }
}