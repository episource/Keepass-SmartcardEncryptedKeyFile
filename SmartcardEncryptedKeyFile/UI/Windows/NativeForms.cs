using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Episource.KeePass.EKF.UI.Windows {
    public static partial class NativeForms {
        
        #region ActiveWindow

        public static Form GetActiveWindow() {
            var activeWinHandle = NativeFormsPinvoke.GetActiveWindow();
            if (activeWinHandle == IntPtr.Zero) {
                return null;
            }

            return Control.FromHandle(activeWinHandle) as Form;
        }
        
        #endregion
        
        #region Desktop
        
        public static IntPtr GetThreadDesktop(uint threadId) {
            var desktop = NativeFormsPinvoke.GetThreadDesktop(threadId);
            if (desktop == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return desktop;
        }

        public static IntPtr GetThreadDesktop(ProcessThread thread) {
            return GetThreadDesktop((uint)thread.Id);
        }

        public static IntPtr GetCurrentThreadDesktop() {
            var currentThread = NativeFormsPinvoke.GetCurrentThreadId();
            return GetThreadDesktop(currentThread);
        }

        public static string GetCurrentThreadDesktopName() {
            return GetDesktopName(GetCurrentThreadDesktop());
        }

        public static void SetCurrentThreadDesktop(IntPtr desktop) {
            if (desktop == IntPtr.Zero) {
                throw new ArgumentException("desktop == IntPtr.Zero", "desktop");
            }

            if (!NativeFormsPinvoke.SetThreadDesktop(desktop)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static string GetDesktopName(IntPtr desktop) {
            if (desktop == IntPtr.Zero) {
                throw new ArgumentException("desktop == IntPtr.Zero", "desktop");
            }
            
            // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
            const int errorInsufficientBuffer = 0x7a;
            
            // UOI_NAME: https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getuserobjectinformationw
            const int uoiNameIndex = 2;

            var bufferSize = 0u;
            NativeFormsPinvoke.GetUserObjectInformation(
                desktop, uoiNameIndex, IntPtr.Zero, bufferSize, ref bufferSize);
            var error = Marshal.GetLastWin32Error();
            if (error != errorInsufficientBuffer) {
                throw new Win32Exception(error);
            }

            var strBuf = IntPtr.Zero;
            try {
                strBuf = Marshal.AllocHGlobal((int) bufferSize);
                if (!NativeFormsPinvoke.GetUserObjectInformation(
                    desktop, uoiNameIndex, strBuf, bufferSize, ref bufferSize)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return Marshal.PtrToStringUni(strBuf);
            } finally {
                Marshal.FreeHGlobal(strBuf);
            }

        }

        public static IntPtr OpenDesktop(string desktopName, bool inherit = false,
            DesktopFlags flags = DesktopFlags.CreateMenu   | DesktopFlags.CreateWindow | DesktopFlags.ReadObjects |
                                 DesktopFlags.WriteObjects | DesktopFlags.SwitchDesktop
        ) {
            var result = NativeFormsPinvoke.OpenDesktop(desktopName, 0, inherit, flags);
            if (result == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return result;
        }

        public static IntPtr OpenInputDesktop(bool inherit = false,
            DesktopFlags flags = DesktopFlags.CreateMenu   | DesktopFlags.CreateWindow | DesktopFlags.ReadObjects |
                                 DesktopFlags.WriteObjects | DesktopFlags.SwitchDesktop
        ) {
            var result = NativeFormsPinvoke.OpenInputDesktop(0, inherit, flags);
            if (result == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return result;
        }

        public static void CloseDesktop(IntPtr desktop) {
            if (!NativeFormsPinvoke.CloseDesktop(desktop)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        
        #endregion
        
        #region Owner

        public static IntPtr GetOwner(IntPtr windowHwnd) {
            return GetWindowLongImpl(windowHwnd, WindowParamIndex.GWL_HWNDPARENT);
        }

        /// <summary>
        /// SetOwner affects the z-Order of windows. Don't confuse with SetParent api, which sets the host of the
        /// control.
        /// </summary>
        public static IntPtr SetOwner(IntPtr windowHwnd, IntPtr newOwner) {
            return SetWindowLongImpl(windowHwnd, WindowParamIndex.GWL_HWNDPARENT, newOwner);
        }
        
        /// <summary>
        /// SetOwner affects the z-Order of windows. Don't confuse with SetParent api, which sets the host of the
        /// control.
        /// </summary>
        public static IntPtr SetOwner(IntPtr windowHwnd, IWin32Window newOwner) {
            return SetOwner(windowHwnd, newOwner.Handle);
        }
        
        #endregion
        
        #region WindowPosition

        public static Rectangle GetWindowRectangle(IntPtr hwnd) {
            var nativeRect = new WindowRect();
            if (!NativeFormsPinvoke.GetWindowRect(hwnd, ref nativeRect)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            
            return new Rectangle(
                nativeRect.Left, nativeRect.Top, 
                nativeRect.Right - nativeRect.Left, nativeRect.Bottom - nativeRect.Top);
        }

        public static void MoveWindow(IntPtr hwnd, Point location) {
            MoveWindow(hwnd, location.X, location.Y);
        }

        public static void MoveWindow(IntPtr hwnd, int x, int y) {
            // https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-setwindowpos
            const uint noSize = 0x0001;
            const uint noZOrder = 0x0004;

            if (!NativeFormsPinvoke.SetWindowPos(
                hwnd, IntPtr.Zero, x, y, 0, 0, noSize | noZOrder)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public static Rectangle CenterWindow(IntPtr hwnd, IntPtr hwndParent) {
            var currentRect = GetWindowRectangle(hwnd);
            var parentRect = GetWindowRectangle(hwndParent);
            
            var newRect = CalculateCenteredRectangle(currentRect, parentRect);
            MoveWindow(hwnd, newRect.Location);
            return newRect;
        }

        public static Rectangle CenterWindow(IntPtr hwnd, Form parent) {
            return CenterWindow(hwnd, parent.Handle);
        }

        public static bool IsCenteredWindow(IntPtr hwnd, IntPtr hwndParent) {
            var currentRect = GetWindowRectangle(hwnd);
            var parentRect = GetWindowRectangle(hwndParent);
            var centeredRect = CalculateCenteredRectangle(currentRect, parentRect);

            return centeredRect == currentRect;
        }

        public static bool IsCenteredWindow(IntPtr hwnd, Form parent) {
            return IsCenteredWindow(hwnd, parent.Handle);
        }

        private static Rectangle CalculateCenteredRectangle(Rectangle currentRect, Rectangle parentRect) {
            var newRect = currentRect;
            newRect.X = parentRect.X + (parentRect.Width  - currentRect.Width)  / 2;
            newRect.Y = parentRect.Y + (parentRect.Height - currentRect.Height) / 2;
            return newRect;
        }
        
        #endregion
        
        #region OtherLayout

        public static bool IsWindowVisible(IntPtr hwnd) {
            return NativeFormsPinvoke.IsWindowVisible(hwnd);
        }

        public static bool IsWindowMaximized(IntPtr hwnd) {
            return NativeFormsPinvoke.IsZoomed(hwnd);
        }
        
        #endregion
    }
}