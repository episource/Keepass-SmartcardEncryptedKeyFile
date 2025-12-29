using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
        /// <summary>
        /// Subset of crypt32 certificate context property id.
        /// Reference: https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        /// </summary>
        private enum CertContextPropId : int {
            CERT_KEY_PROV_HANDLE_PROP_ID = 1,
            CERT_KEY_PROV_INFO_PROP_ID = 2,
            CERT_KEY_CONTEXT_PROP_ID = 5,
            CERT_SMART_CARD_DATA_PROP_ID = 16,
            CERT_NCRYPT_KEY_HANDLE_PROP_ID = 78,
            CERT_NCRYPT_KEY_HANDLE_TRANSFER_PROP_ID = 99,
            CERT_HCRYPTPROV_TRANSFER_PROP_ID = 100
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_id
        [StructLayout(LayoutKind.Sequential)]
        private struct CertId
        {
            public CertIdChoice dwIdChoice;
            
            // actually union - see API documentation
            public CryptDataBlob IssuerOrKeyIdOrHashId;
            public CryptDataBlob IssuerSerialNumber;
            
            public bool IsMatchingCert(X509Certificate2 recipientCert) {
                switch (this.dwIdChoice) {
                    case CertIdChoice.CERT_ID_ISSUER_SERIAL_NUMBER:
                        return 
                            this.IssuerOrKeyIdOrHashId.CopyToByteArray().SequenceEqual(recipientCert.IssuerName.RawData)
                            && this.IssuerSerialNumber.CopyToByteArray().SequenceEqual(recipientCert.GetSerialNumber());
                    case CertIdChoice.CERT_ID_KEY_IDENTIFIER: {
                        var keyIdExtension = recipientCert.GetSubjectKeyIdentifierExtension();
                        return keyIdExtension != null
                               && this.IssuerOrKeyIdOrHashId.CopyToByteArray().SequenceEqual(keyIdExtension.RawData);
                    }
                    default: {
                        return false;
                    }
                }
            }
        }
        
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        private enum CertIdChoice : uint
        {
            CERT_ID_ISSUER_SERIAL_NUMBER = 1,
            CERT_ID_KEY_IDENTIFIER = 2,
            CERT_ID_SHA1_HASH = 3,
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_key_context
        [StructLayout(LayoutKind.Sequential)]
        private struct CertKeyContext {
            public uint cbSize;
            public IntPtr hCryptOrNCryptHandle;
            public CryptPrivateKeySpec dwKeySpec;
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_public_key_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CertPublicKeyInfo {
            public CryptAlgorithmIdentifier Algorithm;
            public CryptDataBlob PublicKey;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_public_key_info
        /// variant without (nested) string member to be used in c# union declaration
        /// See also: CertPublicKeyInfo
        [StructLayout(LayoutKind.Sequential)]
        private struct CertPublicKeyInfoPrimitive {
            public CryptAlgorithmIdentifierPrimitive Algorithm;
            public CryptBitBlob PublicKey;
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
        private enum CryptAcquireCertificatePrivateKeyFlags {
            CRYPT_ACQUIRE_CACHE_FLAG             = 0x00001,
            CRYPT_ACQUIRE_USE_PROV_INFO_FLAG     = 0x00002,
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