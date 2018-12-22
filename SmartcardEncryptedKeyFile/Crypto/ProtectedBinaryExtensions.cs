using KeePassLib.Security;

namespace Episource.KeePass.EKF.Crypto {
    public static class ProtectedBinaryExtensions {
        public static ProtectedBinary Protect(this byte[] plaintext) {
            return new ProtectedBinary(bEnableProtection: true, pbData: plaintext);
        }
    }
}