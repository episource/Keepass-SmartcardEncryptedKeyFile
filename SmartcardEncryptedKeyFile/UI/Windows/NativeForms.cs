using System;
using System.ComponentModel;
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
    }
}