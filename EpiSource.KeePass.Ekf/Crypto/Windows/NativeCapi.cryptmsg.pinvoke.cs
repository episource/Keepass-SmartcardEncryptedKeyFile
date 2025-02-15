using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
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
        
        private sealed class CryptMsgHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public CryptMsgHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                return NativeCryptMsgPinvoke.CryptMsgClose(this.handle);
            }
        }
        
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
    }
}