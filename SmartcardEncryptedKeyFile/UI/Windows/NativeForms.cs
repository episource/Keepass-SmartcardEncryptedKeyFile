using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Episource.KeePass.EKF.UI.Windows {
    public static class NativeForms {

        /// <summary>
        /// Subset of the nIndex values valid for GetWindowLong:
        /// https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getwindowlongw
        /// </summary>
        private enum WindowParamIndex {
            GWL_EXSTYLE = -20,
            GWL_HWNDPARENT = -8,
            GWL_STYLE = -16
        }

        /// <summary>
        /// Subset of: https://docs.microsoft.com/de-de/windows/desktop/winstation/desktop-security-and-access-rights
        /// </summary>
        [Flags]
        public enum DesktopFlags : uint {
            CreateMenu = 0x0004,
            CreateWindow = 0x0002,
            Enumerate = 0x0040,
            HookControl = 0x0008,
            JournalPlayback = 0x0020,
            JournalRecord = 0x0010,
            ReadObjects = 0x0001,
            SwitchDesktop = 0x0100,
            WriteObjects = 0x0080
        }
        
        [DllImport("user32.dll", EntryPoint = "GetActiveWindow", CharSet = CharSet.Auto)]
        private static extern IntPtr GetActiveWindowNative();
        
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetWindowLong(IntPtr hWnd, int nIndex);
        
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowLong(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
        
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
        
        [DllImport("User32.dll", EntryPoint = "OpenDesktop", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenDesktopNative(
            [MarshalAs(UnmanagedType.LPWStr)] string lpszDesktop, int dwFlags,
            [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            [MarshalAs(UnmanagedType.U4)] DesktopFlags dwDesiredAccess
        );

        [DllImport("User32.dll", EntryPoint = "OpenInputDesktop", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenInputDesktopNative(
            int dwFlags, [MarshalAs(UnmanagedType.Bool)] bool fInherit,
            [MarshalAs(UnmanagedType.U4)] DesktopFlags dwDesiredAccess
        );

        [DllImport("User32.dll", EntryPoint = "CloseDesktop", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseDesktopNative(IntPtr hDesktop);
        
        [DllImport("User32.dll", EntryPoint = "GetThreadDesktop", SetLastError = true)]
        private static extern IntPtr GetThreadDesktopNative(uint dwThreadId);
        
        [DllImport("User32.dll", EntryPoint = "SetThreadDesktop", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetThreadDesktopNative(IntPtr hDesktop);
        
        [DllImport("Kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetUserObjectInformation(
            IntPtr hObj, int nIndex, IntPtr pvInfo, uint nLength, ref uint lpnLengthNeeded
        );

        private static IntPtr GetWindowLongImpl(IntPtr hWnd, WindowParamIndex nIndex) {
            var result = IntPtr.Size == 4 
                ? GetWindowLong(hWnd, (int)nIndex) 
                : GetWindowLongPtr(hWnd, (int)nIndex);

            if (result == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return result;
        }
        
        private static IntPtr SetWindowLongImpl(IntPtr hWnd, WindowParamIndex nIndex, IntPtr dwNewLong) {
            var result = IntPtr.Size == 4 
                ? SetWindowLong(hWnd, (int)nIndex, dwNewLong) 
                : SetWindowLongPtr(hWnd, (int)nIndex, dwNewLong);

            if (result == IntPtr.Zero && Marshal.GetLastWin32Error() != 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return result;
        }

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

        public static Form GetActiveWindow() {
            var activeWinHandle = GetActiveWindowNative();
            if (activeWinHandle == IntPtr.Zero) {
                return null;
            }

            return Control.FromHandle(activeWinHandle) as Form;
        }

        public static IntPtr GetThreadDesktop(uint threadId) {
            var desktop = GetThreadDesktopNative(threadId);
            if (desktop == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return desktop;
        }

        public static IntPtr GetThreadDesktop(ProcessThread thread) {
            return GetThreadDesktop((uint)thread.Id);
        }

        public static IntPtr GetCurrentThreadDesktop() {
            var currentThread = GetCurrentThreadId();
            return GetThreadDesktop(currentThread);
        }

        public static string GetCurrentThreadDesktopName() {
            return GetDesktopName(GetCurrentThreadDesktop());
        }

        public static void SetCurrentThreadDesktop(IntPtr desktop) {
            if (desktop == IntPtr.Zero) {
                throw new ArgumentException("desktop == IntPtr.Zero", "desktop");
            }

            if (!SetThreadDesktopNative(desktop)) {
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
            GetUserObjectInformation(desktop, uoiNameIndex, IntPtr.Zero, bufferSize, ref bufferSize);
            var error = Marshal.GetLastWin32Error();
            if (error != errorInsufficientBuffer) {
                throw new Win32Exception(error);
            }

            var strBuf = IntPtr.Zero;
            try {
                strBuf = Marshal.AllocHGlobal((int) bufferSize);
                if (!GetUserObjectInformation(desktop, uoiNameIndex, strBuf, bufferSize, ref bufferSize)) {
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
            var result = OpenDesktopNative(desktopName, 0, inherit, flags);
            if (result == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return result;
        }

        public static IntPtr OpenInputDesktop(bool inherit = false,
            DesktopFlags flags = DesktopFlags.CreateMenu   | DesktopFlags.CreateWindow | DesktopFlags.ReadObjects |
                                 DesktopFlags.WriteObjects | DesktopFlags.SwitchDesktop
        ) {
            var result = OpenInputDesktopNative(0, inherit, flags);
            if (result == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return result;
        }

        public static void CloseDesktop(IntPtr desktop) {
            if (!CloseDesktopNative(desktop)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}