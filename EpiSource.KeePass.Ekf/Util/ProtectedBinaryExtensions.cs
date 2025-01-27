using System;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
    public static class ProtectedBinaryExtensions {
        public static PortableProtectedBinary ToPortable(this ProtectedBinary protectedBinary) {
            return PortableProtectedBinary.Move(protectedBinary.ReadData());
        }

        public static ProtectedBinary ToKeepass(this PortableProtectedBinary protectedBinary) {
            var plaintext = protectedBinary.ReadUnprotected();
            try {
                return new ProtectedBinary(true, plaintext);
            } finally {
                Array.Clear(plaintext, 0, plaintext.Length);
            }
        }
    }
}