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
        public const string AlgGroupEcc = "1.2.840.10045.2.1";
        public const string AlgKeyAgreeDhSinglePassStdParamsSha256 = "1.3.132.1.11.1";
        public const string AlgKeyAgreeDhSinglePassStdParamsSha384 = "1.3.132.1.11.2";
        public const string AlgKeyAgreeDhSinglePassStdParamsSha512 = "1.3.132.1.11.3";
        public const string AlgSsdh = "1.2.840.113549.1.9.16.3.10";
        
        /// ASN Octet String encoded data
        public const string GenericCmsData = "1.2.840.113549.1.7.1";

        /// Select key derivation function (hash) wrt. RFC 5753 recommendations (page 31).
        ///
        /// SHA512 can be disabled for compatibility with default windows CMS implementation
        /// by setting <c>noSha512=true</c>. This is a deviation from RFC 5753 recommendations.
        /// 
        /// Default Windows CMS implementation (at least up to Win 11 25H2) without custom
        /// PFN_CMSG_EXPORT_KEY_AGREE hook does not support SHA512 key derivation. The only
        /// supported KDF variants implemented by default implementation
        /// Crypt32.dll: are 1.3.133.16.840.63.0.2 (SHA-1), 1.3.132.1.11.1 (SHA-256) and
        /// 1.3.132.1.11.2 (SHA-384) - 1.3.132.1.11.3 (SHA-512) is handled with
        /// LastError= ERROR_INVALID_PARAMETER.
        public static string GetAlgKeyAgreeDhSinglePassStdParamsSha(int bits, bool noSha512=false) {
            if (bits <= 256) {
                return AlgKeyAgreeDhSinglePassStdParamsSha256;
            }
            if (bits <= 384 || noSha512) {
                return AlgKeyAgreeDhSinglePassStdParamsSha384;
            }
            return AlgKeyAgreeDhSinglePassStdParamsSha512;
        }

    }
}