using System;
using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
        
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
        
        private static class NativeCertPinvoke {

            /// <summary>
            /// The CertGetCertificateContextProperty function retrieves the information contained in an extended property of a certificate context.
            /// Reference: https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certgetcertificatecontextproperty
            /// </summary>
            /// <returns>If the function succeeds, the function returns TRUE. If the function fails, it returns FALSE. For
            /// extended error information, call GetLastError.
            /// </returns>
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CertGetCertificateContextProperty(
                IntPtr pCertContext, CertContextPropId dwPropId, IntPtr pvData, ref int pcbData
            );
            /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CertSetCertificateContextProperty(IntPtr pCertContext, CertContextPropId propertyId, uint dwFlags, IntPtr pvData);
            /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptAcquireCertificatePrivateKey(IntPtr pCert, CryptAcquireCertificatePrivateKeyFlags dwFlags, ref IntPtr pvParameters,
                out IntPtr phCryptProvOrNCryptKey, out CryptPrivateKeySpec pdwKeySpec, out bool pfCallerFreeProvOrNCryptKey);
        }
    }
}