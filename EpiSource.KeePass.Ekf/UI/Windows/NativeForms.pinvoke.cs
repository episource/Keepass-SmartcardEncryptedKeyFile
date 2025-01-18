using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable IdentifierTypo

namespace EpiSource.KeePass.Ekf.UI.Windows {
    public static partial class NativeForms {
        
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
        private const int ERROR_INVALID_WINDOW_HANDLE = 0x578;
        
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
        
        /// <summary>
        /// Subset of the nIndex values valid for GetWindowLong:
        /// https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getwindowlongw
        /// </summary>
        private enum WindowParamIndex {
            GWL_EXSTYLE = -20,
            GWL_HWNDPARENT = -8,
            GWL_STYLE = -16
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WindowRect {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [SuppressMessage("ReSharper", "MemberHidesStaticFromOuterClass")]
        private static class NativeFormsPinvoke {

            [DllImport("user32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetActiveWindow();

            [DllImport("user32.dll", SetLastError = true)]
            public static extern IntPtr GetWindowLong(IntPtr hWnd, int nIndex);

            [DllImport("user32.dll", SetLastError = true)]
            public static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);

            [DllImport("user32.dll", SetLastError = true)]
            public static extern IntPtr SetWindowLong(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

            [DllImport("user32.dll", SetLastError = true)]
            public static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

            [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr OpenDesktop(
                [MarshalAs(UnmanagedType.LPWStr)] string lpszDesktop, int dwFlags,
                [MarshalAs(UnmanagedType.Bool)] bool fInherit,
                [MarshalAs(UnmanagedType.U4)] DesktopFlags dwDesiredAccess
            );

            [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr OpenInputDesktop(
                int dwFlags, [MarshalAs(UnmanagedType.Bool)] bool fInherit,
                [MarshalAs(UnmanagedType.U4)] DesktopFlags dwDesiredAccess
            );

            [DllImport("User32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseDesktop(IntPtr hDesktop);

            [DllImport("User32.dll", SetLastError = true)]
            public static extern IntPtr GetThreadDesktop(uint dwThreadId);

            [DllImport("User32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetThreadDesktop(IntPtr hDesktop);

            [DllImport("Kernel32.dll")]
            public static extern uint GetCurrentThreadId();

            [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetUserObjectInformation(
                IntPtr hObj, int nIndex, IntPtr pvInfo, uint nLength, ref uint lpnLengthNeeded
            );

            [DllImport("User32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetWindowRect(IntPtr hwnd, ref WindowRect lpRect);
            
            [DllImport("User32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

            [DllImport("User32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool IsWindowVisible(IntPtr hwnd);
            
            [DllImport("User32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool IsZoomed(IntPtr hwnd);
            
            [DllImport("user32", SetLastError = true)]
            public static extern int GetWindowThreadProcessId(IntPtr hWnd, out int processId);
            
            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
        }
        
        private static IntPtr GetWindowLongImpl(IntPtr hWnd, WindowParamIndex nIndex) {
            var result = IntPtr.Size == 4
                ? NativeFormsPinvoke.GetWindowLong(hWnd, (int) nIndex)
                : NativeFormsPinvoke.GetWindowLongPtr(hWnd, (int) nIndex);

            if (result == IntPtr.Zero) {
                var nativeErrorCode = Marshal.GetLastWin32Error();
                if (nativeErrorCode == ERROR_INVALID_WINDOW_HANDLE) {
                    throw new InvalidWindowHandleException();
                }
                throw new Win32Exception(nativeErrorCode);
            }

            return result;
        }

        private static IntPtr SetWindowLongImpl(IntPtr hWnd, WindowParamIndex nIndex, IntPtr dwNewLong) {
            var result = IntPtr.Size == 4
                ? NativeFormsPinvoke.SetWindowLong(hWnd, (int) nIndex, dwNewLong)
                : NativeFormsPinvoke.SetWindowLongPtr(hWnd, (int) nIndex, dwNewLong);

            if (result == IntPtr.Zero && Marshal.GetLastWin32Error() != 0) {
                var nativeErrorCode = Marshal.GetLastWin32Error();
                if (nativeErrorCode == ERROR_INVALID_WINDOW_HANDLE) {
                    throw new InvalidWindowHandleException();
                }
                throw new Win32Exception(nativeErrorCode);
            }

            return result;
        }
    }
}