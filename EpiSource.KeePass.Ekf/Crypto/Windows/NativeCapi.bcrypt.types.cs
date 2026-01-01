namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {

        private struct BcryptPublicKey {
            public BCryptKeyHandle KeyHandle;
            public string CngAlgorithmName;
        }
    }
}