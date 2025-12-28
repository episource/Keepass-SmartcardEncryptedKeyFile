using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

using EpiSource.KeePass.Ekf.Util;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
        [Flags]
        private enum CryptMsgControlFlags : uint {
            None = 0,
            CMSG_CRYPT_RELEASE_CONTEXT_FLAG = 0x8000
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_recipient_encode_info
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h#L772
        private enum CryptMsgRecipientChoice : uint {
            CMSG_KEY_TRANS_RECIPIENT = 1,
            CMSG_KEY_AGREE_RECIPIENT = 2,
            CMSG_MAIL_LIST_RECIPIENT = 3,
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
        /// Subset of available types.
        private enum CryptMsgControlType {
            CMSG_CTRL_DECRYPT = 0x02,
            CMSG_CTRL_KEY_TRANS_DECRYPT = 0x10,
            CMSG_CTRL_KEY_AGREE_DECRYPT = 0x11,
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptimportpublickeyinfoex2
        [Flags]
        private enum CryptEncodingTypeFlags : uint {
            None = 0,
            X509_ASN_ENCODING = 0x1,
            PKCS_7_ASN_ENCODING = 0x10000,
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentoencode
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        [Flags]
        private enum CryptMsgFlags : uint {
            None = 0,
            CMSG_BARE_CONTENT_FLAG = 0x1,
            CMSG_LENGTH_ONLY_FLAG = 0x2,
            CMSG_DETACHED_FLAG = 0x4,
            CMSG_AUTHENTICATED_ATTRIBUTES_FLAG = 0x8,
            CMSG_CONTENTS_OCTETS_FLAG = 0x10,
            CMSG_MAX_LENGTH_FLAG = 0x20,
            CMSG_CMS_ENCAPSULATED_CONTENT_FLAG = 0x40,
            CMSG_SIGNED_DATA_NO_SIGN_FLAG = 0x80,
            CMSG_CRYPT_RELEASE_CONTEXT_FLAG = 0x8000
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        /// Subset of available types.
        private enum CryptMsgParamType {
            CMSG_TYPE_PARAM = 1,
            CMSG_CONTENT_PARAM = 2,
            CMSG_CERT_COUNT_PARAM = 11,
            CMSG_CERT_PARAM = 12,
            CMSG_CMS_RECIPIENT_COUNT_PARAM = 33,
            CMSG_CMS_RECIPIENT_INFO_PARAM = 36
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_cms_recipient_info
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        private enum CryptMsgRecipientType {
            CMSG_KEY_TRANS_RECIPIENT = 1,
            CMSG_KEY_AGREE_RECIPIENT = 2,
            CMSG_MAIL_LIST_RECIPIENT = 3
        }

        /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
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
                if (NativeCryptMsgPinvoke.CryptMsgClose(this.handle)) {
                    this.SetHandleAsInvalid();
                    return true;
                }
                return false;
            }
        }
        
        ///  https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_cms_recipient_info
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CmsgCmsRecipientInfo {
            public CryptMsgRecipientType dwRecipientChoice;
            public IntPtr pRecipientInfo; // CmsgKeyTransRecipientInfo | CmsgKeyAgreeRecipientInfo
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
        
        /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/ns-wincrypt-cmsg_ctrl_key_agree_decrypt_para
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CmsgCtrlKeyAgreeDecryptPara {
            public CmsgCtrlKeyAgreeDecryptPara(NcryptOrContextHandle handle, CryptMsgRecipientKeyAgree keyAgreeRecipient, CryptBitBlob originatorPublicKey) {
                this.cbSize = Marshal.SizeOf<CmsgCtrlKeyAgreeDecryptPara>();
                this.hCryptProv = handle;
                this.dwKeySpec = handle.KeySpec;
                this.pKeyAgree = keyAgreeRecipient.RecipientInfoPtrUnsafe;
                this.dwRecipientIndex = keyAgreeRecipient.RecipientIndex;
                this.dwRecipientEncryptedKeyIndex = keyAgreeRecipient.SubIndex;
                this.originatorPublicKey = originatorPublicKey;
            }
            
            private int cbSize;
            private NcryptOrContextHandle hCryptProv;
            private CryptPrivateKeySpec dwKeySpec;
            private IntPtr pKeyAgree; // CmsgKeyAgreeRecipientInfo
            private int dwRecipientIndex;
            private int dwRecipientEncryptedKeyIndex;
            private CryptBitBlob originatorPublicKey;
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_enveloped_encode_info
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CmsgEnvelopedEncodeInfo {
            public uint cbSize;
            public IntPtr hCryptProv;
            public CryptAlgorithmIdentifier ContentEncryptionAlgorithm;
            public IntPtr pvEncryptionAuxInfo; /* Type: depending on algorithm */
            
            // either rgpRecipients or rgCmsRecipients must be != NULL
            public uint cRecipients;
            public IntPtr rgpRecipients; /* Type: CertInfo */
            public IntPtr rgCmsRecipients; /* Type: CmsgRecipientEncodeInfo */
            
            public int cCertEncoded;
            public IntPtr rgCertEncoded; /* Type: CryptDataBlob */
            public int cCrlEncoded;
            public IntPtr rgCrlEncoded; /* Type: CryptDataBlob */
            public int cAttrCertEncoded;
            public IntPtr rgAttrCertEncoded; /* Type: CryptDataBlob */
            public int cUnprotectedAttr;
            public IntPtr rgUnprotectedAttr; /* Type: CryptAttribute */
        }

        /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/ns-wincrypt-cmsg_key_agree_recipient_encode_info
        private enum CmsgKeyAgreeKeyChoice {
            CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE = 1,
            CMSG_KEY_AGREE_STATIC_KEY_CHOICE = 2
        }

        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        private enum CmsgKeyAgreeOriginator : uint {
            CMSG_KEY_AGREE_ORIGINATOR_CERT = 1,
            CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY = 2
        }
        
        /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/ns-wincrypt-cmsg_key_agree_recipient_encode_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CmsgKeyAgreeRecipientEncodeInfo {
            public uint cbSize;
            public CryptAlgorithmIdentifier keyEncryptionAlgorithm;
            public IntPtr pvKeyEncryptionAuxInfo;
            public CryptAlgorithmIdentifier keyWrapAlgorithm;
            public IntPtr pvKeyWrapAuxInfo;
            public IntPtr hCryptProv;
            public uint dwKeySpec;
            public CmsgKeyAgreeKeyChoice dwKeyChoice;
            public IntPtr pEphemeralAlgorithm; // CryptAlgorithmIdentifier
            public CryptDataBlob UserKeyingMaterial;
            public uint cRecipientEncryptedKeys;
            public IntPtr rgpRecipientEncryptedKeys; // CmsgRecipientEncryptedKeyEncodeInfo
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_key_agree_recipient_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CmsgKeyAgreeRecipientInfo {
            public uint dwVersion;
            public CmsgKeyAgreeOriginator dwOriginatorChoice;
            public CmsgKeyAgreeRecipientInfoOriginatorUnion Originator;
            public CryptDataBlob UserKeyingMaterial;
            public CryptAlgorithmIdentifier KeyEncryptionAlgorithm;
            public int cRecipientEncryptedKeys;
            public IntPtr rpgRecipientEncryptedKeys; // CmsgRecipientEncryptedKeyInfo
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_key_agree_recipient_info
        [StructLayout(LayoutKind.Explicit)]
        private struct CmsgKeyAgreeRecipientInfoOriginatorUnion {
            [FieldOffset(0)]
            public CertId OriginatorCertId;
            [FieldOffset(0)]
            public CertPublicKeyInfoPrimitive PublicKey;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_key_trans_recipient_encode_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CmsgKeyTransRecipientEncodeInfo {
            public uint cbSize;
            public CryptAlgorithmIdentifier KeyEncryptionAlgorithm;
            public IntPtr pvKeyEncryptionAuxInfo;
            public IntPtr hCryptProv;
            public CryptBitBlob RecipientPublicKey;
            public CertId RecipientId;
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_key_trans_recipient_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CmsgKeyTransRecipientInfo {
            public uint dwVersion;
            public CertId RecipientId;
            public CryptAlgorithmIdentifier KeyEncryptionAlgorithm;
            public CryptDataBlob EncryptedKey;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_recipient_encode_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CmsgRecipientEncodeInfo {
            public CryptMsgRecipientChoice dwRecipientChoice;
            public IntPtr pCmsRecipientEncodeInfo; /* Type: depending on dwRecipientChoice */
        }

        /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/ns-wincrypt-cmsg_recipient_encrypted_key_encode_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CmsgRecipientEncryptedKeyEncodeInfo {
            public uint cbSize;
            public CryptBitBlob RecipientPublicKey;
            public CertId RecipientId;
            public long Date; // FILETIME
            public IntPtr pOtherAttr; // CryptAttributeTypeValue
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_recipient_encrypted_key_info
        [StructLayout(LayoutKind.Sequential)]
        private struct CmsgRecipientEncryptedKeyInfo {
            public CertId RecipientId;
            public CryptDataBlob EncryptedKey;
            public long Date; // FILETIME
            public IntPtr pOtherAttr; // CryptAttributeTypeValue
        }

        
        private static class NativeCryptMsgPinvoke {
            
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgclose
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgClose(IntPtr handle);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
            [DllImport("Crypt32.dll", EntryPoint = "CryptMsgControl", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgControlDecrypt(CryptMsgHandle hCryptMsg,
                CryptMsgControlFlags dwFlags, CryptMsgControlType dwCtrlType, ref CmsgCtrlDecryptPara pvCtrlPara);
            
            /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
            // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol
            [DllImport("Crypt32.dll", EntryPoint = "CryptMsgControl", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgControlDecryptKeyAgree(CryptMsgHandle hCryptMsg,
                CryptMsgControlFlags dwFlags, CryptMsgControlType dwCtrlType, ref CmsgCtrlKeyAgreeDecryptPara pvCtrlPara);
            
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
            [DllImport("Crypt32.dll", EntryPoint = "CryptMsgGetParam", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgGetParamByteArray(CryptMsgHandle hCryptMsg, CryptMsgParamType dwParamType,
                uint dwIndex, byte[] pvDataDword, ref int pcbDataSize);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
            [DllImport("Crypt32.dll", EntryPoint = "CryptMsgGetParam", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgGetParamDword(CryptMsgHandle hCryptMsg, CryptMsgParamType dwParamType,
                uint dwIndex, ref uint pvDataDword, ref int pcbDataSize);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
            [DllImport("Crypt32.dll", EntryPoint = "CryptMsgGetParam", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgGetParamBuffer(CryptMsgHandle hCryptMsg, CryptMsgParamType dwParamType,
                uint dwIndex, HGlobalHandle pvDataDword, ref int pcbDataSize);
            
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern CryptMsgHandle CryptMsgOpenToDecode(CryptEncodingTypeFlags dwEncodingType,
                CryptMsgFlags dwFlags, CryptMsgType dwMsgType, IntPtr hCryptProv, IntPtr pRecipientInfo,
                IntPtr pStreamInfo);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentoencode
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern CryptMsgHandle CryptMsgOpenToEncode(CryptEncodingTypeFlags dwEncodingType,
                CryptMsgFlags dwFlags, CryptMsgType dwMsgType, CmsgEnvelopedEncodeInfoHandle pvMsgEncodeInfo,
                [MarshalAs(UnmanagedType.LPStr)]string pszInnerContentObjID, IntPtr pStreamInfo);
            /// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgupdate
            [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptMsgUpdate(CryptMsgHandle hCryptMsg, byte[] pbData, uint cbData, bool fFinal);
        }
    }
}