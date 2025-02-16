using System;
using System.Text;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Util {
    
    [Serializable]
    public sealed class PortableProtectedString {   
        
        private readonly PortableProtectedBinary protectedChars;

        private PortableProtectedString(char[] strToCopy, int count) {
            count = Math.Min(count, strToCopy.Length);
            
            var bytes = new byte[2 * count];
            for (var i = 0; i < count; ++i) {
                var cb = BitConverter.GetBytes(strToCopy[i]);
                bytes[i*2] = cb[0];
                bytes[i*2 + 1] = cb[1];
            }
            this.protectedChars = PortableProtectedBinary.Move(bytes);
        }


        public static PortableProtectedString CopyOf(char[] str, int count=-1) {
            return new PortableProtectedString(str, count < 0 ? str.Length : count);
        }
        
        public static PortableProtectedString Move(char[] str) {
            try {
                return CopyOf(str);
            } finally {
                Array.Clear(str, 0, str.Length);
            }
        }

        public static PortableProtectedString FromAscii(PortableProtectedBinary binary, bool trimNullTerminator = false) {
            return FromEncoded(binary, Encoding.ASCII, trimNullTerminator);
        }
        
        public static PortableProtectedString FromUtf8(PortableProtectedBinary binary, bool trimNullTerminator = false) {
            return FromEncoded(binary, Encoding.UTF8, trimNullTerminator);
        }
        
        public static PortableProtectedString FromUtf16(PortableProtectedBinary binary, bool trimNullTerminator = false) {
            return FromEncoded(binary, Encoding.Unicode, trimNullTerminator);
        }

        public static PortableProtectedString FromEncoded(PortableProtectedBinary binary, Encoding encoding, bool trimNullTerminator = false) {
            if (binary == null) {
                return null;
            }
            
            var unprotectedBinary = binary.ReadUnprotected();
            var unprotectedChars = encoding.GetChars(unprotectedBinary);
            Array.Clear(unprotectedBinary, 0, unprotectedBinary.Length);

            int count = unprotectedChars.Length;
            while (count > 0 && unprotectedChars[count - 1] == '\0') {
                count--;
            }
            
            var protectedString = CopyOf(unprotectedChars, count);
            Array.Clear(unprotectedChars, 0, unprotectedChars.Length);
            return protectedString;
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
            return this.ReadUnprotectedEncoded(Encoding.UTF8, nullTerminator);
        }

        public byte[] ReadUnprotectedUtf8NullTerminated() {
            return this.ReadUnprotectedUtf8(true);
        }
        
        public byte[] ReadUnprotectedUtf16(bool nullTerminator = false) {
            return this.ReadUnprotectedEncoded(Encoding.Unicode, nullTerminator);
        }

        public byte[] ReadUnprotectedUtf16NullTerminated() {
            return this.ReadUnprotectedUtf16(true);
        }
        
        public byte[] ReadUnprotectedAscii(bool nullTerminator = false) {
            return this.ReadUnprotectedEncoded(Encoding.ASCII, nullTerminator);
        }

        public byte[] ReadUnprotectedAsciiNullTerminated() {
            return this.ReadUnprotectedAscii(true);
        }

        public byte[] ReadUnprotectedEncoded(Encoding encoding, bool nullTerminator = false) {
            // not using string operations - strings are immutable and cannot be easily overwritten
            var chars = this.ReadUnprotected();
            if (nullTerminator) AppendNull(ref chars);

            try {
                return encoding.GetBytes(chars);
            } finally {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        public byte[] ReadUnprotectedEncodedNullTerminated(Encoding encoding) {
            return this.ReadUnprotectedEncoded(encoding, true);
        }
        
        public PortableProtectedBinary ToUtf8() {
            var unprotectedUtf8 = this.ReadUnprotectedUtf8();
            return PortableProtectedBinary.Move(unprotectedUtf8);
        }

        public PortableProtectedBinary ToUtf8NullTerminated() {
            var unprotectedUtf8 = this.ReadUnprotectedUtf8NullTerminated();
            return PortableProtectedBinary.Move(unprotectedUtf8);
        }

        public PortableProtectedBinary ToUtf16() {
            var unprotectedUtf16 = this.ReadUnprotectedUtf16();
            return PortableProtectedBinary.Move(unprotectedUtf16);
        }

        public PortableProtectedBinary ToUtf16NullTerminated() {
            var unprotectedUtf16 = this.ReadUnprotectedUtf16NullTerminated();
            return PortableProtectedBinary.Move(unprotectedUtf16);
        }

        public PortableProtectedBinary ToAscii() {
            var unprotectedAscii = this.ReadUnprotectedAscii();
            return PortableProtectedBinary.Move(unprotectedAscii);
        }

        public PortableProtectedBinary ToAsciiNullTerminated() {
            var unprotectedAscii = this.ReadUnprotectedAsciiNullTerminated();
            return PortableProtectedBinary.Move(unprotectedAscii);
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

        private static void AppendNull(ref char[] chars) {
            var withNull = new char[chars.Length + 1];
            Array.Copy(chars, 0, withNull, 0, chars.Length);
            
            Array.Clear(chars, 0, chars.Length);
            chars = withNull;
        }
    }
}