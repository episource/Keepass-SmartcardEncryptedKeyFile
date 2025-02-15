using System;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    
    public static partial class NativeCapi {
        
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
        
        [StructLayout(LayoutKind.Sequential)]
        private struct BcryptKeyLengthsStruct
        {
            public uint dwMinLength;
            public uint dwMaxLength;
            public uint dwIncrement;
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
        
        private static class NativeBCryptPinvoke {
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlagsMustBeZero = 0);
            
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptDecrypt(BCryptKeyHandle hKey, HGlobalHandle pbInput, int cbInput, ref BcryptAuthenticatedCipherModeInfo pPaddingInfo,
                HGlobalHandle pbIV, int cbIV, HGlobalHandle pbOutput, int cbOutput, out int pcbResult, int dwFlagsZeroForAesGcm=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptDestroyKey(IntPtr hKey);
            
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptEncrypt(BCryptKeyHandle hKey, HGlobalHandle pbInput, int cbInput, ref BcryptAuthenticatedCipherModeInfo pPaddingInfo,
                HGlobalHandle pbIV, int cbIV, HGlobalHandle pbOutput, int cbOutput, out int pcbResult, int dwFlagsZeroForAesGcm=0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGenerateSymmetricKey(BCryptAlgorithmHandle hAlgorithm, out BCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, PortableProtectedBinaryHandle pbSecret, int cbSecret, uint dwFlagsMustBeZero = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptGetProperty(BCryptAlgorithmHandle hObject, [In] string pszProperty, out BcryptKeyLengthsStruct pbOutput, int cbOutput, out int pcbResult, int dwFlagsMustBeZero = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptOpenAlgorithmProvider(out BCryptAlgorithmHandle phAlgorithm, [In] string pszAlgId,  string pszImplementation = null, int dwFlags = 0);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty
            [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern NTStatusUtil.NTStatus BCryptSetProperty(BCryptAlgorithmHandle hObject, [In] string pszProperty, [In] byte[] pbInput, int cbInput, int dwFlagsMustBeZero = 0);
        }
    }
}