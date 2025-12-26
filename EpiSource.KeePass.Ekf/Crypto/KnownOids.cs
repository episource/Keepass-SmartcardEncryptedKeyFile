namespace EpiSource.KeePass.Ekf.Crypto {
    public static class KnownOids {
        public const string AlgAesKeyWrap128 = "2.16.840.1.101.3.4.1.5";
        public const string AlgAesKeyWrap192 = "2.16.840.1.101.3.4.1.25";
        public const string AlgAesKeyWrap256 = "2.16.840.1.101.3.4.1.45";
        public const string AlgAesCbc128 = "2.16.840.1.101.3.4.1.2";
        public const string AlgAesCbc192 = "2.16.840.1.101.3.4.1.22";
        public const string AlgAesCbc256 = "2.16.840.1.101.3.4.1.42";
        public const string AlgAesGcm128 = "2.16.840.1.101.3.4.1.6";
        public const string AlgAesGcm192 = "2.16.840.1.101.3.4.1.26";
        public const string AlgAesGcm256 = "2.16.840.1.101.3.4.1.46";
        public const string AlgDhRsa = "1.2.840.113549.1.3.1";
        public const string AlgEsdhSmimeRsa = "1.2.840.113549.1.9.16.3.5";
        public const string AlgEsdhX942 = "1.2.840.10046.2.1";
        public const string AlgKeyAgreeDhSinglePassStdParamsSha256 = "1.3.132.1.11.1";
        public const string AlgKeyAgreeDhSinglePassStdParamsSha384 = "1.3.132.1.11.2";
        public const string AlgKeyAgreeDhSinglePassStdParamsSha512 = "1.3.132.1.11.3";
        public const string AlgSsdh = "1.2.840.113549.1.9.16.3.10";
        
        /// ASN Octet String encoded data
        public const string GenericCmsData = "1.2.840.113549.1.7.1";

        public static string GetAlgKeyAgreeDhSinglePassStdParamsSha(int bits) {
            if (bits <= 256) {
                return AlgKeyAgreeDhSinglePassStdParamsSha256;
            }
            if (bits <= 384) {
                return AlgKeyAgreeDhSinglePassStdParamsSha384;
            }
            return AlgKeyAgreeDhSinglePassStdParamsSha512;
        }

    }
}