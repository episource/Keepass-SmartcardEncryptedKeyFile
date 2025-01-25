using System;
using System.Text;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
    public static class ProtectedStringExtensions {
        public static byte[] ReadUnicode(this ProtectedString s, bool nullTerminator = false) {
            // not using string operations - strings are immutable and cannot be easily overwritten
            var chars = s.ReadChars();
            if (nullTerminator) appendNull(ref chars);

            try {
                return Encoding.Unicode.GetBytes(chars);
            } finally {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        public static byte[] ReadUnicodeNullTerminated(this ProtectedString s) {
            return ReadUnicode(s, true);
        }
        
        public static byte[] ReadAscii(this ProtectedString s, bool nullTerminator = false) {
            // not using string operations - strings are immutable and cannot be easily overwritten
            var chars = s.ReadChars();
            if (nullTerminator) appendNull(ref chars);

            try {
                return Encoding.ASCII.GetBytes(chars);
            } finally {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        public static byte[] ReadAsciiNullTerminated(this ProtectedString s) {
            return ReadAscii(s, true);
        }

        private static void appendNull(ref char[] chars) {
            var withNull = new char[chars.Length + 1];
            Array.Copy(chars, 0, withNull, 0, chars.Length);
            
            Array.Clear(chars, 0, chars.Length);
            chars = withNull;
        }

    }
}