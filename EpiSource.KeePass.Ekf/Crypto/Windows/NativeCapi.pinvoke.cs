#region

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Windows.Forms;

using Microsoft.Win32.SafeHandles;

#endregion

// ReSharper disable UnusedMember.Local
// ReSharper disable IdentifierTypo

// ReSharper disable InconsistentNaming
// ReSharper disable EnumUnderlyingTypeIsInt

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
        
        // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_ctrl_decrypt_para
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        [SuppressMessage("ReSharper", "PrivateFieldCanBeConvertedToLocalVariable")]
        [SuppressMessage("ReSharper", "FieldCanBeMadeReadOnly.Local")]
        private struct CmsgCtrlDecryptPara {
            public CmsgCtrlDecryptPara(NcryptOrContextHandle handle, int recipientIndex) {
                this.cbSize = Marshal.SizeOf<CmsgCtrlDecryptPara>();
                this.hCryptProv = handle;
                this.dwKeySpec = handle.KeySpec;
                this.dwRecipientIndex = recipientIndex;
            }

            private int cbSize;
            private NcryptOrContextHandle hCryptProv;
            private CryptPrivateKeySpec dwKeySpec;
            private int dwRecipientIndex;
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
        
        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public uint dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public BcryptAuthModeFlags dwFlags;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_KEY_LENGTHS_STRUCT
        {
            public uint dwMinLength;
            public uint dwMaxLength;
            public uint dwIncrement;
        }

        private sealed class CryptMsgHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public CryptMsgHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                return NativeCryptMsgPinvoke.CryptMsgClose(this.handle);
            }
        }

        private abstract class NcryptOrContextHandle : SafeHandleZeroOrMinusOneIsInvalid {

            private readonly CryptPrivateKeySpec keySpec;

            protected NcryptOrContextHandle(CryptPrivateKeySpec keySpec) : base(true) {
                this.keySpec = keySpec;
            }
            protected NcryptOrContextHandle(IntPtr handle, bool isOwned, CryptPrivateKeySpec keySpec) : base(isOwned) {
                this.keySpec = keySpec;
                this.SetHandle(handle);
            }

            public static NcryptOrContextHandle of(IntPtr handle, bool isOwned, CryptPrivateKeySpec keySpec) {
                if (keySpec == CryptPrivateKeySpec.CERT_NCRYPT_KEY_SPEC) {
                    return new NCryptContextHandle(handle, isOwned);
                }
                return new CryptContextHandle(handle, isOwned, keySpec);
            }

            public CryptPrivateKeySpec KeySpec {
                get { return this.keySpec; }
            }
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

        private sealed class NCryptContextHandle : NcryptOrContextHandle {
            public NCryptContextHandle() : base(CryptPrivateKeySpec.CERT_NCRYPT_KEY_SPEC) { }
            
            public NCryptContextHandle(IntPtr handle, bool isOwned) : base(handle, isOwned, CryptPrivateKeySpec.CERT_NCRYPT_KEY_SPEC) { 
                this.SetHandle(handle);
            }
            
            protected override bool ReleaseHandle() {
                return NativeNCryptPinvoke.NCryptFreeObject(this.handle) == 0x0;
            }
        }

        private sealed class BCryptAlgorithmHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public BCryptAlgorithmHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                return NativeBCryptPinvoke.BCryptCloseAlgorithmProvider(this.handle).EnsureSuccess();
            }
        }
        
        private sealed class BCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public BCryptKeyHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                return NativeBCryptPinvoke.BCryptDestroyKey(this.handle).EnsureSuccess();
            }
        }

        private static class NativeCapiPinvoke {

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
            public  static extern bool CertSetCertificateContextProperty(IntPtr pCertContext, CertContextPropId propertyId, uint dwFlags, IntPtr pvData);
            /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptAcquireCertificatePrivateKey(IntPtr pCert, CryptAcquireCertificatePrivateKeyFlags dwFlags, ref IntPtr pvParameters,
                out IntPtr phCryptProvOrNCryptKey, out CryptPrivateKeySpec pdwKeySpec, out bool pfCallerFreeProvOrNCryptKey);
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

        private static class NativeCryptMsgPinvoke {

            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgclose
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgClose(IntPtr handle);
            /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgControl(CryptMsgHandle hCryptMsg,
                CryptMsgControlFlags dwFlags, CryptMsgControlType dwCtrlType, ref CmsgCtrlDecryptPara pvCtrlPara);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
            [DllImport("Crypt32.dll", EntryPoint = "CryptMsgGetParam", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgGetParamDword(CryptMsgHandle hCryptMsg, CryptMsgParamType dwParamType,
                uint dwIndex, ref uint pvDataDword, ref int pcbDataSize);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
            [DllImport("Crypt32.dll", EntryPoint = "CryptMsgGetParam", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgGetParamByteArray(CryptMsgHandle hCryptMsg, CryptMsgParamType dwParamType,
                uint dwIndex, byte[] pvDataDword, ref int pcbDataSize);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern CryptMsgHandle CryptMsgOpenToDecode(CryptMsgEncodingTypeFlags dwMsgEncodingType,
                CryptMsgFlags dwFlags, CryptMsgType dwMsgType, IntPtr hCryptProv, IntPtr pRecipientInfo,
                IntPtr pStreamInfo);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgupdate
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgUpdate(CryptMsgHandle hCryptMsg, byte[] pbData, uint cbData, bool fFinal);
        }

        private static class NativeBCryptPinvoke {
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlagsMustBeZero = 0);
            
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptDecrypt(BCryptKeyHandle hKey, HGlobalHandle pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                HGlobalHandle pbIV, int cbIV, HGlobalHandle pbOutput, int cbOutput, out int pcbResult, int dwFlagsZeroForAesGcm=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptDestroyKey(IntPtr hKey);
            
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptEncrypt(BCryptKeyHandle hKey, HGlobalHandle pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                HGlobalHandle pbIV, int cbIV, HGlobalHandle pbOutput, int cbOutput, out int pcbResult, int dwFlagsZeroForAesGcm=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGenerateSymmetricKey(BCryptAlgorithmHandle hAlgorithm, out BCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, PortableProtectedBinaryHandle pbSecret, int cbSecret, uint dwFlagsMustBeZero = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGetProperty(BCryptAlgorithmHandle hObject, [In] string pszProperty, out BCRYPT_KEY_LENGTHS_STRUCT pbOutput, int cbOutput, out int pcbResult, int dwFlagsMustBeZero = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptOpenAlgorithmProvider(out BCryptAlgorithmHandle phAlgorithm, [In] string pszAlgId,  string pszImplementation = null, int dwFlags = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptSetProperty(BCryptAlgorithmHandle hObject, [In] string pszProperty, [In] byte[] pbInput, int cbInput, int dwFlagsMustBeZero = 0);
        }

        private static class NativeNCryptPinvoke {
            /// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject
            [DllImport("Ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
            public static extern int NCryptFreeObject(IntPtr hObject);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty
            [DllImport("Ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
            public static extern CryptoResult NCryptGetProperty(
                NCryptContextHandle hObject, string pszProperty,  byte[] pbOutput, int cbOutput,
                out int pcbResult, NCryptGetPropertyFlags dwFlags);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty
            [DllImport("Ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
            public static extern CryptoResult NCryptSetProperty(
                NCryptContextHandle hObject, string pszProperty,  byte[] pbInput, int cbInput,
                NCryptSetPropertyFlags dwFlags);
        }
    }
}