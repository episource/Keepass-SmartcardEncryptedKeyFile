using System;
using System.Text;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
    
    [Serializable]
    public sealed class PortableProtectedString {   
        
        private readonly PortableProtectedBinary protectedChars;

        private PortableProtectedString(char[] strToCopy) {
            var bytes = new byte[2 * strToCopy.Length];
            for (var i = 0; i < strToCopy.Length; ++i) {
                var cb = BitConverter.GetBytes(strToCopy[i]);
                bytes[i*2] = cb[0];
                bytes[i*2 + 1] = cb[1];
            }
            this.protectedChars = PortableProtectedBinary.Move(bytes);
        }


        public static PortableProtectedString CopyOf(char[] str) {
            return new PortableProtectedString(str);
        }
        
        public static PortableProtectedString Move(char[] str) {
            try {
                return CopyOf(str);
            } finally {
                Array.Clear(str, 0, str.Length);
            }
        }

        public int Length {
            get { return this.protectedChars.Length / 2; }
        }
        
        public char[] ReadUnprotected() {
            var bytes = this.protectedChars.ReadUnprotected();
            try {
                var chars = new char[this.Length];
                for (var i = 0; i < chars.Length; ++i) {
                    chars[i] = BitConverter.ToChar(bytes, i * 2);
                }
                return chars;
            } finally {
                Array.Clear(bytes, 0, bytes.Length);
            }
        }
        
        public byte[] ReadUnprotectedUtf8(bool nullTerminator = false) {
            // not using string operations - strings are immutable and cannot be easily overwritten
            var chars = this.ReadUnprotected();
            if (nullTerminator) appendNull(ref chars);

            try {
                return Encoding.UTF8.GetBytes(chars);
            } finally {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        public byte[] ReadUnprotectedUtf8NullTerminated() {
            return this.ReadUnprotectedUtf8(true);
        }
        
        public byte[] ReadUnprotectedUtf16(bool nullTerminator = false) {
            // not using string operations - strings are immutable and cannot be easily overwritten
            var chars = this.ReadUnprotected();
            if (nullTerminator) appendNull(ref chars);

            try {
                return Encoding.Unicode.GetBytes(chars);
            } finally {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        public byte[] ReadUnprotectedUtf16NullTerminated() {
            return this.ReadUnprotectedUtf16(true);
        }
        
        public byte[] ReadUnprotectedAscii(bool nullTerminator = false) {
            // not using string operations - strings are immutable and cannot be easily overwritten
            var chars = this.ReadUnprotected();
            if (nullTerminator) appendNull(ref chars);

            try {
                return Encoding.ASCII.GetBytes(chars);
            } finally {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        public byte[] ReadUnprotectedAsciiNullTerminated() {
            return this.ReadUnprotectedAscii(true);
        }

        public override bool Equals(object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is PortableProtectedString && this.Equals((PortableProtectedString) obj);
        }
        
        private bool Equals(PortableProtectedString other) {
            return Equals(this.protectedChars, other.protectedChars);
        }
        public override int GetHashCode() {
            return (this.protectedChars != null ? this.protectedChars.GetHashCode() : 0);
        }

        private static void appendNull(ref char[] chars) {
            var withNull = new char[chars.Length + 1];
            Array.Copy(chars, 0, withNull, 0, chars.Length);
            
            Array.Clear(chars, 0, chars.Length);
            chars = withNull;
        }
    }
}