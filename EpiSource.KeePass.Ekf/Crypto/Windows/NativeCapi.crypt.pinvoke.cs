using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using EpiSource.KeePass.Ekf.Util;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public partial class NativeCapi {
        
        /// https://learn.microsoft.com/en-us/windows/win32/seccng/cng-interface-identifiers
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/bcrypt.h
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-tools/widl/include/ncrypt.h
        private enum CngInterfaceIdentifier {
            BCRYPT_CIPHER_INTERFACE = 0x00000001,
            BCRYPT_HASH_INTERFACE = 0x00000002,
            BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE = 0x00000003,
            BCRYPT_SECRET_AGREEMENT_INTERFACE = 0x00000004,
            BCRYPT_SIGNATURE_INTERFACE = 0x00000005,
            BCRYPT_RNG_INTERFACE = 0x00000006,
            BCRYPT_KEY_DERIVATION_INTERFACE = 0x00000007,
            
            NCRYPT_KEY_STORAGE_INTERFACE = 0x00010001,
            NCRYPT_SCHANNEL_INTERFACE = 0x00010002,
            NCRYPT_SCHANNEL_SIGNATURE_INTERFACE = 0x00010003,
            NCRYPT_KEY_PROTECTION_INTERFACE = 0x00010004
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_oid_info
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        private enum CryptAlgGroupId {
            CRYPT_HASH_ALG_OID_GROUP_ID = 1,
            CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2,
            CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3,
            CRYPT_SIGN_ALG_OID_GROUP_ID = 4,
            CRYPT_RDN_ATTR_OID_GROUP_ID = 5,
            CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6,
            CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7,
            CRYPT_POLICY_OID_GROUP_ID = 8,
            CRYPT_TEMPLATE_OID_GROUP_ID = 9,
            CRYPT_KDF_OID_GROUP_ID = 10
        }

        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        private enum CryptAlgClassId {
            ALG_CLASS_ANY = (0),
            ALG_CLASS_SIGNATURE = (1 << 13),
            ALG_CLASS_MSG_ENCRYPT = (2 << 13),
            ALG_CLASS_DATA_ENCRYPT = (3 << 13),
            ALG_CLASS_HASH = (4 << 13),
            ALG_CLASS_KEY_EXCHANGE = (5 << 13),
            ALG_CLASS_ALL = (7 << 13)
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CryptAlgorithmIdentifier {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;
            public CryptDataBlob Parameters;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier
        /// Variant without string member to be used in c# union declaration
        /// See also: CryptAlgorithmIdentifier
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CryptAlgorithmIdentifierPrimitive{
            public IntPtr pszObjId; // LPStr
            public CryptDataBlob Parameters;
        }

        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_attribute
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CryptAttribute {
            internal IntPtr pszObjId;
            internal uint cValue;
            internal IntPtr rgValue;
        }

        /// https://learn.microsoft.com/de-de/windows/win32/api/wincrypt/ns-wincrypt-crypt_attribute_type_value
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CryptAttributeTypeValue {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;
            public CryptDataBlob Value;
        }
        
        /// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa381414(v=vs.85)
        [StructLayout(LayoutKind.Sequential)]
        private struct CryptDataBlob {
            public uint cbData;
            public IntPtr pbData;

            public byte[] CopyToByteArray() {
                var array = new byte[this.cbData];
                Marshal.Copy(this.pbData, array, 0, array.Length);
                return array;
            }
        }
        
        private class CryptDataBlobListHandle : HGlobalHandle {

            private readonly int count;
            private readonly MarshaledStructureHandleCollection itemHandles = new  MarshaledStructureHandleCollection();
            public CryptDataBlobListHandle() : base(true) {}

            public CryptDataBlobListHandle(byte[] blob)
                : this(new List<byte[]> { blob } ) {
            }

            public CryptDataBlobListHandle(List<byte[]> blobs)
                : base(blobs.Count * Marshal.SizeOf<CryptDataBlob>() + blobs.Select(c => c.Length).Sum()) {
                this.count = blobs.Count;

                var nextBlobAddr = this.DangerousGetHandle();
                var nextDataAddr = nextBlobAddr + blobs.Count * Marshal.SizeOf<CryptDataBlob>();

                foreach (var blobData in blobs) {
                    var blob = new CryptDataBlob() {
                        cbData = (uint)blobData.Length,
                        pbData = nextDataAddr
                    };
                    
                    Marshal.Copy(blobData, 0, nextDataAddr, blobData.Length);
                    Marshal.StructureToPtr(blob, nextBlobAddr, false);
                    this.itemHandles.AddStructure<CryptDataBlob>(nextBlobAddr);

                    nextBlobAddr += Marshal.SizeOf<CryptDataBlob>();
                    nextDataAddr +=  blobData.Length;
                }
            }
            
            public int Count {
                get {
                    return this.count;
                }
            }

            protected override bool ReleaseHandle() {
                this.itemHandles.Dispose();
                return base.ReleaseHandle();
            }
        }
        
        /// https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/include/wincrypt.h
        [StructLayout(LayoutKind.Sequential)]
        private struct CryptBitBlob {
            public uint cbData;
            public IntPtr pbData;
            public uint cUnusedBits;
            
            public byte[] CopyToByteArray() {
                var array = new byte[this.cbData];
                Marshal.Copy(this.pbData, array, 0, array.Length);
                return array;
            }
        }
        
        private class CryptBitBlobListHandle : HGlobalHandle {

            private readonly int count;
            private readonly MarshaledStructureHandleCollection itemHandles = new  MarshaledStructureHandleCollection();
            public CryptBitBlobListHandle() : base(true) {}

            public CryptBitBlobListHandle(List<byte[]> blobs)
                : base(blobs.Count * Marshal.SizeOf<CryptBitBlob>() + blobs.Select(c => c.Length).Sum()) {
                this.count = blobs.Count;

                var nextBlobAddr = this.DangerousGetHandle();
                var nextDataAddr = nextBlobAddr + blobs.Count * Marshal.SizeOf<CryptDataBlob>();

                foreach (var fullByteBlobData in blobs) {
                    var blob = new CryptBitBlob() {
                        cbData = (uint)fullByteBlobData.Length,
                        pbData = nextDataAddr,
                        cUnusedBits = 0
                    };
                    
                    Marshal.Copy(fullByteBlobData, 0, nextDataAddr, fullByteBlobData.Length);
                    Marshal.StructureToPtr(blob, nextBlobAddr, false);
                    this.itemHandles.AddStructure<CryptDataBlob>(nextBlobAddr);

                    nextBlobAddr += Marshal.SizeOf<CryptDataBlob>();
                    nextDataAddr +=  fullByteBlobData.Length;
                }
            }
            
            public int Count {
                get {
                    return this.count;
                }
            }
        }

        private enum CryptFindOIDInfoGroupId : uint {
            CRYPT_OID_ALL = 0,
            CRYPT_OID_DISABLE_SEARCH_DS_FLAG = 0x80000000,
        }

        [Flags]
        private enum CryptFindOIDInfoKeyTypeFlag : uint {
            CRYPT_OID_INFO_OID_KEY = 1,
            CRYPT_OID_INFO_NAME_KEY = 2,
            CRYPT_OID_INFO_ALGID_KEY = 3,
            CRYPT_OID_INFO_SIGN_KEY = 4,
            CRYPT_OID_INFO_CNG_ALGID_KEY = 5,
            CRYPT_OID_INFO_CNG_SIGN_KEY = 6,

            CRYPT_OID_INFO_OID_KEY_FLAGS_MASK = 0xffff0000,
            CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG = 0x80000000,
            CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG = 0x40000000
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CryptOidInfo {
            public uint cbSize;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszOID;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszName;
            public CryptAlgGroupId dwGroupId;

            // union member. Alternative meaning applies if dwGroupId is not:
            // - CRYPT_HASH_ALG_OID_GROUP_ID
            // - CRYPT_ENCRYPT_ALG_OID_GROUP_ID
            // - CRYPT_PUBKEY_ALG_OID_GROUP_ID
            // - CRYPT_SIGN_ALG_OID_GROUP_ID
            // AlgId is a bitfield ALG_CLASS(CryptAlgClassId)|ALG_TYPE|ALG_SID
            public int AlgId;
            public CryptDataBlob ExtraInfo;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCNGAlgid;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCNGExtraAlgid;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_public_key_info
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CryptPublicKeyInfo {
            public CryptAlgorithmIdentifier Algorithm;
            public CryptBitBlob PublicKey;
        }
        
        private class CryptPublicKeyInfoHandle : SafeHandleMinusOneIsInvalid {
            
            public CryptPublicKeyInfoHandle() : base(true) {}

            public CryptPublicKeyInfoHandle(X509Certificate2 cert)
                : base(true) {

                var algorithmParamsLength = cert.GetKeyAlgorithmParameters().Length;
                var pubKeyDataLength = cert.GetPublicKey().Length;
                this.SetHandle(Marshal.AllocHGlobal(Marshal.SizeOf<CryptPublicKeyInfo>() + algorithmParamsLength + pubKeyDataLength));

                
                var algorithmParamsAddr = this.handle + Marshal.SizeOf<CryptPublicKeyInfo>();
                Marshal.Copy(cert.GetKeyAlgorithmParameters(), 0 , algorithmParamsAddr, algorithmParamsLength);
                var pubKeyDataAddr = algorithmParamsAddr + algorithmParamsLength;
                Marshal.Copy(cert.GetPublicKey(), 0, pubKeyDataAddr, cert.GetPublicKey().Length);

                var pubKeyInfo = new CryptPublicKeyInfo() {
                    Algorithm = {
                        pszObjId = cert.GetKeyAlgorithm(),
                        Parameters = new CryptDataBlob() {
                            cbData = (uint) algorithmParamsLength,
                            pbData = algorithmParamsAddr,
                        }
                    },
                    PublicKey = {
                        cbData = (uint) pubKeyDataLength,
                        pbData = pubKeyDataAddr,
                        cUnusedBits = 0
                    }
                };
                
                Marshal.StructureToPtr(pubKeyInfo, this.handle, false);
            }

            protected override bool ReleaseHandle() {
                Marshal.DestroyStructure<CryptPublicKeyInfo>(this.handle);
                Marshal.FreeHGlobal(this.handle);
                this.SetHandleAsInvalid();
                
                return true;
            }
        }

        private static class NativeCryptPinvoke {
            
            [DllImport("crypt32.dll", SetLastError = true)]
            public static extern bool CryptImportPublicKeyInfoEx2(CryptEncodingTypeFlags dwCertEncodingType,
                CryptPublicKeyInfoHandle pInfo, CryptFindOIDInfoKeyTypeFlag dwFlags, IntPtr pvAuxInfo, out BCryptKeyHandle phKey);
            
        }
    }
}