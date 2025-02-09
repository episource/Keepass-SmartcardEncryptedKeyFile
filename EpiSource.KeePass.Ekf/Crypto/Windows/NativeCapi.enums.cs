using System;


namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
        
        /// <summary>
        /// Set of relevant error codes.
        /// Reference: https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/include/winerror.h
        /// </summary>
        internal enum CryptoResult : uint {
            ERROR_SUCCESS = 0,
            ERROR_MORE_DATA           = 0xEA,
            NTE_BAD_UID = 0x80090001,
            NTE_BAD_HASH = 0x80090002,
            NTE_BAD_KEY = 0x80090003,
            NTE_BAD_LEN = 0x80090004,
            NTE_BAD_DATA = 0x80090005,
            NTE_BAD_SIGNATURE = 0x80090006,
            NTE_BAD_VER = 0x80090007,
            NTE_BAD_ALGID = 0x80090008,
            NTE_BAD_FLAGS = 0x80090009,
            NTE_BAD_TYPE = 0x8009000A,
            NTE_BAD_KEY_STATE = 0x8009000B,
            NTE_BAD_HASH_STATE = 0x8009000C,
            NTE_NO_KEY = 0x8009000D,
            NTE_NO_MEMORY = 0x8009000E,
            NTE_EXISTS = 0x8009000F,
            NTE_PERM = 0x80090010,
            NTE_NOT_FOUND = 0x80090011,
            NTE_DOUBLE_ENCRYPT = 0x80090012,
            NTE_BAD_PROVIDER = 0x80090013,
            NTE_BAD_PROV_TYPE = 0x80090014,
            NTE_BAD_PUBLIC_KEY = 0x80090015,
            NTE_BAD_KEYSET = 0x80090016,
            NTE_PROV_TYPE_NOT_DEF = 0x80090017,
            NTE_PROV_TYPE_ENTRY_BAD = 0x80090018,
            NTE_KEYSET_NOT_DEF = 0x80090019,
            NTE_KEYSET_ENTRY_BAD = 0x8009001A,
            NTE_PROV_TYPE_NO_MATCH = 0x8009001B,
            NTE_SIGNATURE_FILE_BAD = 0x8009001C,
            NTE_PROVIDER_DLL_FAIL = 0x8009001D,
            NTE_PROV_DLL_NOT_FOUND = 0x8009001E,
            NTE_BAD_KEYSET_PARAM = 0x8009001F,
            NTE_FAIL = 0x80090020,
            NTE_SYS_ERR = 0x80090021,
            NTE_BUFFER_TOO_SMALL = 0x80090028,
            NTE_NOT_SUPPORTED = 0x80090029,
            NTE_NO_MORE_ITEMS = 0x8009002a,
            NTE_SILENT_CONTEXT = 0x80090022,
            NTE_TOKEN_KEYSET_STORAGE_FULL = 0x80090023,
            NTE_TEMPORARY_PROFILE = 0x80090024,
            NTE_FIXEDPARAMETER = 0x80090025,
            NTE_INVALID_HANDLE = 0x80090026,
            NTE_INVALID_PARAMETER = 0x80090027,
            NTE_BUFFERS_OVERLAP = 0x8009002B,
            NTE_DECRYPTION_FAILURE = 0x8009002C,
            NTE_INTERNAL_ERROR = 0x8009002D,
            NTE_UI_REQUIRED = 0x8009002E,
            NTE_HMAC_NOT_SUPPORTED = 0x8009002F,
            NTE_DEVICE_NOT_READY = 0x80090030,
            NTE_AUTHENTICATION_IGNORED = 0x80090031,
            NTE_VALIDATION_FAILED = 0x80090032,
            NTE_INCORRECT_PASSWORD = 0x80090033,
            NTE_ENCRYPTION_FAILURE = 0x80090034,
            NTE_DEVICE_NOT_FOUND = 0x80090035,
            CRYPT_E_NOT_FOUND         = 0x80092004,
            
            /// wrong pin
            SCARD_W_WRONG_CHV         = 0x8010006B,
            SCARD_W_CHV_BLOCKED       = 0x8010006C,
            SCARD_W_CANCELLED_BY_USER = 0x8010006E,
        }

        /// <summary>
        /// Subset of crypt32 certificate context property id.
        /// Reference: https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        /// </summary>
        private enum CertContextPropId : int {
            CERT_KEY_PROV_HANDLE_PROP_ID = 1,
            CERT_KEY_PROV_INFO_PROP_ID = 2
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
        private enum CryptAcquireCertificatePrivateKeyFlags {
            CRYPT_ACQUIRE_CACHE_FLAG             = 0x00001,
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG       = 0x00004,
            CRYPT_ACQUIRE_NO_HEALING             = 0x00008,
            CRYPT_ACQUIRE_SILENT_FLAG            = 0x00040,
            CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG     = 0x00080,
            CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG  = 0x10000,
            CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x20000,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG   = 0x40000,
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
        [Flags]
        private enum CryptAcquireContextFlags : uint {
            None = 0,
            CRYPT_VERIFYCONTEXT = 0xf0000000,
            CRYPT_NEWKEYSET = 0x8,
            CRYPT_MACHINE_KEYSET = 0x20,
            CRYPT_DELETEKEYSET = 0x10,
            CRYPT_SILENT = 0x40,
            CRYPT_DEFAULT_CONTAINER_OPTIONAL = 0x80
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
        [Flags]
        private enum CryptMsgControlFlags : uint {
            None = 0,
            CMSG_CRYPT_RELEASE_CONTEXT_FLAG = 0x8000
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
        /// Subset of available types.
        private enum CryptMsgControlType {
            CMSG_CTRL_DECRYPT = 0x02
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode
        [Flags]
        private enum CryptMsgEncodingTypeFlags : uint {
            None = 0,
            X509_ASN_ENCODING = 0x1,
            PKCS_7_ASN_ENCODING = 0x10000,
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode
        [Flags]
        private enum CryptMsgFlags : uint {
            None = 0,
            CMSG_DETACHED_FLAG = 0x4,
            CMSG_CRYPT_RELEASE_CONTEXT_FLAG = 0x8000
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
        /// Subset of available types.
        private enum CryptMsgParamType {
            CMSG_TYPE_PARAM = 1,
            CMSG_CONTENT_PARAM = 2
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode
        private enum CryptMsgType : uint {
            RetrieveTypeFromHeader = 0,
            CMSG_DATA = 1,
            CMSG_SIGNED = 2,
            CMSG_ENVELOPED = 3,
            CMSG_SIGNED_AND_ENVELOPED = 4,
            CMSG_HASHED = 5,
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
        private enum CryptPrivateKeySpec {
            UNDEFINED             = 0,
            AT_KEYEXCHANGE        = 1,
            AT_SIGNATURE          = 2,
            CERT_NCRYPT_KEY_SPEC  = unchecked((int)0xffffffff),
        }

        /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/nf-wincrypt-cryptgetprovparam
        private enum CryptGetProvParamType {
            PP_ENUMALGS            = 0x01,
            PP_ENUMCONTAINERS      = 0x02,
            PP_IMPTYPE             = 0x03,
            PP_NAME                = 0x04,
            PP_VERSION             = 0x05,
            PP_CONTAINER           = 0x06,
            PP_CHANGE_PASSWORD     = 0x07,
            PP_KEYSET_SEC_DESCR    = 0x08,
            PP_CERTCHAIN           = 0x09,
            PP_KEY_TYPE_SUBTYPE    = 0x0A,
            PP_PROVTYPE            = 0x10,
            PP_KEYSTORAGE          = 0x11,
            PP_APPLI_CERT          = 0x12,
            PP_SYM_KEYSIZE         = 0x13,
            PP_SESSION_KEYSIZE     = 0x14,
            PP_UI_PROMPT           = 0x15,
            PP_ENUM_ALGS_EX        = 0x16,
            PP_ENUMMANDROOTS       = 0x19,
            PP_ENUMSELECTROOTS     = 0x1A,
            PP_KEYSET_TYPE         = 0x1B,
            PP_ADMIN_PIN           = 0x1F,
            PP_KEYEXCHANGE_PIN     = 0x20,
            PP_SIGNATURE_PIN       = 0x21,
            PP_SIG_KEYSIZE_INC     = 0x22,
            PP_KEYX_KEYSIZE_INC    = 0x23,
            PP_UNIQUE_CONTAINER    = 0x24,
            PP_SGC_INFO            = 0x25,
            PP_USE_HARDWARE_RNG    = 0x26,
            PP_KEYSPEC             = 0x27,
            PP_ENUMEX_SIGNING_PROT = 0x28,
            PP_CRYPT_COUNT_KEY_USE = 0x29,
            PP_USER_CERTSTORE      = 0x2A,
            PP_SMARTCARD_READER    = 0x2B,
            PP_SMARTCARD_GUID      = 0x2D,
            PP_ROOT_CERTSTORE      = 0x2E,
        }

        /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/nf-wincrypt-cryptsetprovparam
        private enum CryptSetProvParamType {
            PP_CLIENT_HWND            = 0x01,
            PP_KEYSET_SEC_DESCR       = CryptGetProvParamType.PP_KEYSET_SEC_DESCR,
            PP_UI_PROMPT              = CryptGetProvParamType.PP_UI_PROMPT,
            PP_DELETEKEY              = 0x18,
            PP_KEYEXCHANGE_PIN        = CryptGetProvParamType.PP_KEYEXCHANGE_PIN,
            PP_SIGNATURE_PIN          = CryptGetProvParamType.PP_SIGNATURE_PIN,
            PP_USE_HARDWARE_RNG       = CryptGetProvParamType.PP_USE_HARDWARE_RNG,
            PP_USER_CERTSTORE         = CryptGetProvParamType.PP_USER_CERTSTORE,
            PP_SMARTCARD_READER       = CryptGetProvParamType.PP_SMARTCARD_READER,
            PP_PIN_PROMPT_STRING      = 0x2C,
            PP_SMARTCARD_GUID         = CryptGetProvParamType.PP_SMARTCARD_GUID,
            PP_ROOT_CERTSTORE         = CryptGetProvParamType.PP_ROOT_CERTSTORE,
            PP_SECURE_KEYEXCHANGE_PIN = 0x2F,
            PP_SECURE_SIGNATURE_PIN   = 0x30,
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info
        [Flags]
        private enum KeyProvInfoFlags : int {
            None = 0,

            CERT_SET_KEY_CONTEXT_PROP_ID = 0x1,
            CERT_SET_KEY_PROV_HANDLE_PROP_ID = 0x1,

            NCRYPT_MACHINE_KEY_FLAG = 0x20,
            CRYPT_MACHINE_KEYSET = 0x20,

            
            NCRYPT_SILENT_FLAG = 0x40,
            CRYPT_SILENT = 0x40
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty
        [Flags]
        private enum NCryptGetPropertyFlags {
            None = 0x0,
            
            OWNER_SECURITY_INFORMATION = 0x00000001,
            GROUP_SECURITY_INFORMATION = 0x00000002,
            DACL_SECURITY_INFORMATION  = 0x00000004,
            SACL_SECURITY_INFORMATION  = 0x00000008,
            
            NCRYPT_SILENT_FLAG         = NCryptSetPropertyFlags.NCRYPT_SILENT_FLAG,
            NCRYPT_PERSIST_ONLY_FLAG   = NCryptSetPropertyFlags.NCRYPT_PERSIST_ONLY_FLAG,
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty
        [Flags]
        private enum NCryptSetPropertyFlags {
            None                     = 0x0,
            NCRYPT_SILENT_FLAG       = 0x00000040,
            NCRYPT_PERSIST_ONLY_FLAG = 0x40000000,
            NCRYPT_PERSIST_FLAG      = unchecked((int)0x80000000)
        }
    }
}