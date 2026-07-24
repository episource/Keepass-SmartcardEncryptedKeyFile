using System;

using EpiSource.KeePass.Ekf.Crypto;

using Episource.KeePass.EKF.Resources;

namespace EpiSource.KeePass.Ekf.UI.Util {
    public static class KeyPairExtensions {
        public static String DescribePrivateKeyState(this KeyPairModel kpm) {
            return kpm.KeyPair.DescribePrivateKeyState();
        }

        public static String DescribePrivateKeyState(this IKeyPair kp) {
            if (kp.IsMismatch == true) {
                return Strings.KeyPairExtension_KeyStateMismatch;
            }
            if (kp.IsAccessible) {
                return Strings.KeyPairExtension_KeyStateConnected;
            }
            return Strings.KeyPairExtension_KeyStateNotConnected;
        }
    }
}