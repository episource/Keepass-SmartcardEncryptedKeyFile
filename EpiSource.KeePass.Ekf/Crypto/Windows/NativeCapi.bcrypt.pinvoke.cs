using System;
using System.Runtime.InteropServices;

using EpiSource.KeePass.Ekf.Util;
using EpiSource.KeePass.Ekf.Util.Windows;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    
    public static partial class NativeCapi {

        /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumalgorithms
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/bcrypt.h
        [Flags]
        private enum BcryptOperations {
            BCRYPT_CIPHER_OPERATION = 0x00000001,
            BCRYPT_HASH_OPERATION = 0x00000002,
            BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x00000004,
            BCRYPT_SECRET_AGREEMENT_OPERATION = 0x00000008,
            BCRYPT_SIGNATURE_OPERATION = 0x00000010,
            BCRYPT_RNG_OPERATION = 0x00000020,
            BCRYPT_KEY_DERIVATION_OPERATION = 0x00000040
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_algorithm_identifier
        private struct BcryptAlgorithmIdentifier {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;
            public CngInterfaceIdentifier dwClass;
            public int dwFlags;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
        [StructLayout(LayoutKind.Sequential)]
        private struct BcryptAuthenticatedCipherModeInfo
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
            public int dwFlags;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_key_lengths_struct
        [StructLayout(LayoutKind.Sequential)]
        private struct BcryptKeyLengthsStruct
        {
            public uint dwMinLength;
            public uint dwMaxLength;
            public uint dwIncrement;
        }

        private abstract class BCryptHandle : SafeHandleMinusOneIsInvalid {
            
            public BCryptHandle(bool owner) : base(owner) { }
        }
        
        private sealed class BCryptAlgorithmHandle : BCryptHandle {
            public BCryptAlgorithmHandle() : base(true) { }

            public BCryptAlgorithmHandle(IntPtr nativeHandle, bool ownsHandle) : base(ownsHandle) {
                this.SetHandle(nativeHandle);
            }

            protected override bool ReleaseHandle() {
                return NativeBCryptPinvoke.BCryptCloseAlgorithmProvider(this.handle).EnsureSuccess();
            }
        }
        
        private sealed class BCryptKeyHandle : BCryptHandle {
            public BCryptKeyHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                if (NativeBCryptPinvoke.BCryptDestroyKey(this.handle).EnsureSuccess()) {
                    this.SetHandleAsInvalid();
                    return true;
                }
                return false;
            }
        }
        
        private sealed class BCryptSecretHandle : BCryptHandle {
            public BCryptSecretHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                if (NativeBCryptPinvoke.BCryptDestroySecret(this.handle).EnsureSuccess()) {
                    this.SetHandleAsInvalid();
                    return true;
                }
                return false;
            }
        }
        
        private static class NativeBCryptPinvoke {
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlagsMustBeZero = 0);
            
            [DllImport("bcrypt.dll", EntryPoint = "BCryptDecrypt", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptDecryptAuthenticatedCipher(BCryptKeyHandle hKey, HGlobalHandle pbInput, int cbInput, ref BcryptAuthenticatedCipherModeInfo pPaddingInfo,
                HGlobalHandle pbIV, int cbIV, HGlobalHandle pbOutput, int cbOutput, out int pcbResult, int dwFlagsZeroForAesGcm=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptDestroyKey(IntPtr hKey);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroysecret
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptDestroySecret(IntPtr hSecret);
            
            [DllImport("bcrypt.dll", EntryPoint = "BCryptEncrypt", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptEncrypt(BCryptKeyHandle hKey, HGlobalHandle pbInput, int cbInput, IntPtr pPaddingInfo,
                HGlobalHandle pbIV, int cbIV, HGlobalHandle pbOutput, int cbOutput, out int pcbResult, int dwFlags=0);
            
            [DllImport("bcrypt.dll", EntryPoint = "BCryptEncrypt", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptEncryptAuthenticatedCipher(BCryptKeyHandle hKey, HGlobalHandle pbInput, int cbInput, ref BcryptAuthenticatedCipherModeInfo pPaddingInfo,
                HGlobalHandle pbIV, int cbIV, HGlobalHandle pbOutput, int cbOutput, out int pcbResult, int dwFlagsZeroForAesGcm=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumalgorithms
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptEnumAlgorithms(BcryptOperations dwAlgOperations, out int pAlgCount, ref IntPtr ppAlgList, int dwFlags=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfinalizekeypair
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptFinalizeKeyPair(BCryptKeyHandle phKey, int dwFlags=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptfreebuffer
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern void BCryptFreeBuffer(IntPtr pvBuffer);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratekeypair
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGenerateKeyPair(BCryptAlgorithmHandle hAlgorithm, out BCryptKeyHandle phKey, int dwLength, int dwFlags);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGenerateSymmetricKey(BCryptAlgorithmHandle hAlgorithm, out BCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, PortableProtectedBinaryHandle pbSecret, int cbSecret, uint dwFlagsMustBeZero = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
            [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGetPropertyKeyLengthStruct(BCryptHandle hObject, [In] string pszProperty, out BcryptKeyLengthsStruct pbOutput, int cbOutput, out int pcbResult, int dwFlagsMustBeZero = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
            [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGetPropertyInt32(BCryptHandle hObject, [In] string pszProperty, out int pbOutput, int cbOutput, out int pcbResult, int dwFlagsMustBeZero = 0);
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
            [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGetPropertyIntPtr(BCryptHandle hObject, [In] string pszProperty, out IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlagsMustBeZero = 0);
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
            [DllImport("bcrypt.dll", EntryPoint = "BCryptGetProperty", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGetPropertyBinary(BCryptHandle hObject, [In] string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlagsMustBeZero = 0);

            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptOpenAlgorithmProvider(out BCryptAlgorithmHandle phAlgorithm, [In] string pszAlgId,  string pszImplementation = null, int dwFlags = 0);
            
            /// https://learn.microsoft.com/de-de/windows/win32/api/bcrypt/nf-bcrypt-bcryptsecretagreement
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptSecretAgreement(BCryptKeyHandle hPrivKey, BCryptKeyHandle hPubKey, out BCryptSecretHandle phAgreedSecret, int dwFlags=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptSetProperty(BCryptAlgorithmHandle hObject, [In] string pszProperty, [In] byte[] pbInput, int cbInput, int dwFlagsMustBeZero = 0);
        }
    }
}