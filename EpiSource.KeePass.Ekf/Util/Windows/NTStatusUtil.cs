using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static class NTStatusUtil {
        public enum NTStatus : uint {
            STATUS_SUCCESS = 0x00,
            STATUS_INVALID_HANDLE = 0xC0000008,
            STATUS_INVALID_PARAMETER = 0xC000000D,
            STATUS_NO_MEMORY = 0xC0000017,
            STATUS_BUFFER_TOO_SMALL = 0xC0000023,
            STATUS_NOT_SUPPORTED = 0xC00000BB,
            STATUS_INVALID_BUFFER_SIZE = 0xC0000206,
            STATUS_NOT_FOUND = 0xC0000225,
            STATUS_AUTH_TAG_MISMATCH = 0xC000A002,
        }
        
        public static bool EnsureSuccess(this NTStatus status) {
            if (status == NTStatus.STATUS_SUCCESS) {
                return true;
            }
            
            var ntdll = PInvoke.LoadLibrary("ntdll.dll");
            if (ntdll.IsInvalid) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            
            
            var sb = new StringBuilder(1024);
            var size = PInvoke.FormatMessage(
                (int)(FormatMessageFlags.IGNORE_INSERTS | FormatMessageFlags.FROM_HMODULE),
                ntdll, status, 0, sb, sb.Capacity, IntPtr.Zero);
            if (size == 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            sb.Length = size;
            throw new Win32Exception(unchecked((int) status), sb.ToString());
        }

        [Flags]
        private enum FormatMessageFlags {
            IGNORE_INSERTS = 0x200,
            FROM_HMODULE = 0x800,
            FROM_SYSTEM = 0x1000
        }

        private sealed class LibraryHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public LibraryHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                return PInvoke.FreeLibrary(this.handle);
            }
        }

        private static class PInvoke {
            [DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)]
            public static extern int FormatMessage(int dwFlags, LibraryHandle lpSource,
                NTStatus dwMessageId, int dwLanguageId, [Out]StringBuilder lpBuffer,
                int nSize, IntPtr va_list_arguments);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern LibraryHandle LoadLibrary(string lpFileName);
            
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool FreeLibrary(IntPtr library);
        }

    }
}