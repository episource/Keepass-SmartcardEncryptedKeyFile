using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
// ReSharper disable InconsistentNaming
// ReSharper disable EnumUnderlyingTypeIsInt

namespace Episource.KeePass.EKF.Crypto.Windows {
    public static class NativeCapi {
        /// <summary>
        /// Subset of crypt32 certificate context property id.
        /// Reference: https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        /// </summary>
        private enum CertContextPropId : int {
            CERT_KEY_PROV_INFO_PROP_ID = 2
        }

        // ReSharper disable once EnumUnderlyingTypeIsInt
        [Flags]
        private enum KeyProvInfoFlags : int {
            // Sames as CERT_SET_KEY_CONTEXT_PROP_ID
            // ReSharper disable once UnusedMember.Local
            CERT_SET_KEY_PROV_HANDLE_PROP_ID = 0x1,
            
            // Same as NCRYPT_MACHINE_KEY_FLAG
            CRYPT_MACHINE_KEYSET = 0x20,
            
            // Same as NCRYPT_SILENT_FLAG
            CRYPT_SILENT = 0x40
            
        }

        /// <summary>
        /// Set of relevant error codes.
        /// Reference: https://github.com/Alexpux/mingw-w64/blob/d0d7f784833bbb0b2d279310ddc6afb52fe47a46/mingw-w64-headers/include/winerror.h
        /// </summary>
        private enum ErrorCodes : int {
            CRYPT_E_NOT_FOUND = unchecked((int) 0x80092004)
        }
        
        /// <summary>
        /// The CRYPT_KEY_PROV_INFO structure contains information about a key container within a cryptographic service provider (CSP).
        /// Reference: https://docs.microsoft.com/de-de/windows/desktop/api/wincrypt/ns-wincrypt-_crypt_key_prov_info
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Local")]
        [SuppressMessage("ReSharper", "MemberCanBePrivate.Local")]
        private struct CRYPT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszProvName;
            public uint dwProvType;
            public uint dwFlags;
            public uint cProvParam;
            public IntPtr rgProvParam;
            public uint dwKeySpec;
        }
        
        /// <summary>
        /// The CertGetCertificateContextProperty function retrieves the information contained in an extended property of a certificate context.
        /// Reference: https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certgetcertificatecontextproperty
        /// </summary>
        /// <returns>If the function succeeds, the function returns TRUE. If the function fails, it returns FALSE. For
        /// extended error information, call GetLastError.
        /// </returns>
        [DllImport("Crypt32.dll", EntryPoint = "CertGetCertificateContextProperty", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CertGetCertificateContextProperty(
            IntPtr pCertContext, CertContextPropId dwPropId, IntPtr pvData, ref int pcbData
        );

        /// <summary>
        /// Returns the CspParameters of a certificate with MS-CAPI backed private key.
        /// </summary>
        /// <param name="cert">The certificate to query.</param>
        /// <returns>The private key parameters if there is a private key, otherwise <code>null</code></returns>
        /// <exception cref="CryptographicException">Querying the private key parameters failed unexpectedly.</exception>
        public static CspParameters GetParameters(X509Certificate cert) {
            Func<CspParameters> onFailure = () => {
                var errorCode = Marshal.GetLastWin32Error();
                if (errorCode == (int)ErrorCodes.CRYPT_E_NOT_FOUND) {
                    return null;
                }

                throw new CryptographicException(errorCode);
            };
            
            var pcbData = 0;
            var success = CertGetCertificateContextProperty(cert.Handle, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                IntPtr.Zero, ref pcbData);
            if (!success) {
                return onFailure();
            }

            var pvData = Marshal.AllocHGlobal(pcbData);
            try {
                success = CertGetCertificateContextProperty(cert.Handle, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    pvData, ref pcbData);
                
                if (!success) {
                    return onFailure();
                }

                var nativeKeyInfo = Marshal.PtrToStructure<CRYPT_KEY_PROV_INFO>(pvData);
                
                // Let's ignore ParentWindowHandle & KeyPassword for now
                var cspParams = new CspParameters {
                    KeyContainerName = nativeKeyInfo.pwszContainerName,
                    ProviderName = nativeKeyInfo.pwszProvName,
                    ProviderType = (int)nativeKeyInfo.dwProvType,
                    KeyNumber = (int)nativeKeyInfo.dwKeySpec,
                    Flags = CspProviderFlags.NoFlags
                };

                cspParams.Flags |=
                    ((KeyProvInfoFlags)nativeKeyInfo.dwFlags & KeyProvInfoFlags.CRYPT_MACHINE_KEYSET) ==
                    KeyProvInfoFlags.CRYPT_MACHINE_KEYSET
                        ? CspProviderFlags.UseMachineKeyStore : CspProviderFlags.NoFlags;
                cspParams.Flags |=
                    ((KeyProvInfoFlags)nativeKeyInfo.dwFlags & KeyProvInfoFlags.CRYPT_SILENT) ==
                    KeyProvInfoFlags.CRYPT_SILENT
                        ? CspProviderFlags.NoPrompt : CspProviderFlags.NoFlags;
                    
                return cspParams;

            } finally {
                Marshal.FreeHGlobal(pvData);
            }
        }
    }
}