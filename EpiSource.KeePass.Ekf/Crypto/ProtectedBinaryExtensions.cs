using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
    public static class ProtectedBinaryExtensions {
        public static ProtectedBinary Protect(this byte[] plaintext) {
            return new ProtectedBinary(bEnableProtection: true, pbData: plaintext);
        }
    }
}