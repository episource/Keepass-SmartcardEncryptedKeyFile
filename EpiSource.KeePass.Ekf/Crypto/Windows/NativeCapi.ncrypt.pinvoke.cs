using System;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
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
        
        private sealed class NCryptContextHandle : NcryptOrContextHandle {
            public NCryptContextHandle() : base(CryptPrivateKeySpec.CERT_NCRYPT_KEY_SPEC) { }
            
            public NCryptContextHandle(IntPtr handle, bool isOwned) : base(handle, isOwned, CryptPrivateKeySpec.CERT_NCRYPT_KEY_SPEC) { 
                this.SetHandle(handle);
            }
            
            protected override bool ReleaseHandle() {
                return NativeNCryptPinvoke.NCryptFreeObject(this.handle) == 0x0;
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