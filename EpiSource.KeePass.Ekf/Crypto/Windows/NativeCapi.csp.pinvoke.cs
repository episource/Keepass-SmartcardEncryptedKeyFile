#region

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

#endregion

// ReSharper disable UnusedMember.Local
// ReSharper disable IdentifierTypo

// ReSharper disable InconsistentNaming
// ReSharper disable EnumUnderlyingTypeIsInt

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
        
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

        /// <summary>
        /// The CRYPT_KEY_PROV_INFO structure contains information about a key container within a cryptographic service provider (CSP).
        /// Reference: https://docs.microsoft.com/de-de/windows/desktop/api/wincrypt/ns-wincrypt-_crypt_key_prov_info
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Local")]
        [SuppressMessage("ReSharper", "MemberCanBePrivate.Local")]
        private struct CryptKeyProvInfo {
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszContainerName;
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszProvName;
            public uint dwProvType;
            public uint dwFlags;
            public uint cProvParam;
            public IntPtr rgProvParam;
            public uint dwKeySpec;
        }
        
        private sealed class CryptContextHandle : NcryptOrContextHandle {
            public CryptContextHandle() : base(CryptPrivateKeySpec.UNDEFINED) { }

            public CryptContextHandle(IntPtr handle, bool isOwned, CryptPrivateKeySpec keySpec) : base(handle, isOwned, keySpec) {
                if (keySpec == CryptPrivateKeySpec.CERT_NCRYPT_KEY_SPEC) {
                    throw new ArgumentOutOfRangeException("keySpec", "Not a legacy csp handle");
                }
                
                this.SetHandle(handle);
            }

            protected override bool ReleaseHandle() {
                return NativeLegacyCapiPinvoke.CryptReleaseContext(this.handle);
            }
        }

        private static class NativeLegacyCapiPinvoke {
            
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
            [DllImport("Advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptAcquireContext(out CryptContextHandle hProv,
                string pszContainer, string pszProvider, int dwProvType, CryptAcquireContextFlags dwFlags);

            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext
            [DllImport("Advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags = 0);

            /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgetprovparam
            [DllImport("AdvApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptGetProvParam(CryptContextHandle hProv, CryptGetProvParamType param, byte[] pbData,
                ref int pdwDataLen, int dwFlags);
            
            /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/nf-wincrypt-cryptsetprovparam
            [DllImport("AdvApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptSetProvParam(CryptContextHandle hProv, CryptSetProvParamType param, byte[] pbData,
                int dwFlags);
            
        }

    }
}