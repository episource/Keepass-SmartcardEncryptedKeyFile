using System;
using System.Text;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Util {
    public static class ProtectedStringExtensions {
        
        public static PortableProtectedString ToPortable(this ProtectedString protectedString) {
            return PortableProtectedString.Move(protectedString.ReadChars());
        }

        public static ProtectedString ToKeepass(this PortableProtectedString protectedString) {
            var plaintext = protectedString.ReadUnprotectedUtf8();
            try {
                return new ProtectedString(true, plaintext);
            } finally {
                Array.Clear(plaintext, 0, plaintext.Length);
            }
        }
        
    }
}