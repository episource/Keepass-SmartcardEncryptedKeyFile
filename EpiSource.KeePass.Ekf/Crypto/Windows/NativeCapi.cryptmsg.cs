using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;
using EpiSource.KeePass.Ekf.Util;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
        private static IReadOnlyList<CryptMsgRecipient> GetRecipientsDangerous(CryptMsgHandle cryptMsgHandle, IEnumerable<X509Certificate2> additionalCerts=null, bool withoutCerts=false) {
            var availableCerts = withoutCerts ? Array.Empty<X509Certificate2>() : GetAvailableCertificates(
                GetEnvelopedCmsCerts(cryptMsgHandle).Concat(additionalCerts ?? Array.Empty<X509Certificate2>()));
            
            uint numRecipients = 0;
            int numRecipientsSize = sizeof(uint);

            PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgGetParamDword(
                cryptMsgHandle, CryptMsgParamType.CMSG_CMS_RECIPIENT_COUNT_PARAM, 0, ref numRecipients, ref numRecipientsSize));

            var recipients = new List<CryptMsgRecipient>((int)numRecipients);
            for (var i = 0; i < numRecipients; ++i) {
                var recipientInfoBufferSize = 0;
                
                PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgGetParamBuffer(
                    cryptMsgHandle, CryptMsgParamType.CMSG_CMS_RECIPIENT_INFO_PARAM, (uint)i, new HGlobalHandle(), ref recipientInfoBufferSize),
                    r => r.Result || r.Win32ErrorCode == (int)CryptoResult.ERROR_MORE_DATA);

                var buffer = new HGlobalHandle(recipientInfoBufferSize);
                PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgGetParamBuffer(
                    cryptMsgHandle, CryptMsgParamType.CMSG_CMS_RECIPIENT_INFO_PARAM, (uint) i, buffer, ref recipientInfoBufferSize));
                var recipientInfo = Marshal.PtrToStructure<CmsgCmsRecipientInfo>(buffer.DangerousGetHandle());

                
                if (recipientInfo.dwRecipientChoice == CryptMsgRecipientType.CMSG_KEY_TRANS_RECIPIENT) {
                    recipients.AddRange(new CryptMsgRecipientKeyTrans(buffer, i, recipientInfo.pRecipientInfo)
                        .WithMatchingRecipient(availableCerts, preserveRecipientWithoutCertificate:withoutCerts));
                } else if (recipientInfo.dwRecipientChoice == CryptMsgRecipientType.CMSG_KEY_AGREE_RECIPIENT) {
                    var recipientNative = Marshal.PtrToStructure<CmsgKeyAgreeRecipientInfo>(recipientInfo.pRecipientInfo);

                    IReadOnlyList<byte> originatorPublicKey = null;
                    if (recipientNative.dwOriginatorChoice == CmsgKeyAgreeOriginator.CMSG_KEY_AGREE_ORIGINATOR_CERT) {
                        var originatorCertId = recipientNative.Originator.OriginatorCertId;
                        foreach (var cert in availableCerts) {
                            if (originatorCertId.IsMatchingCert(cert)) {
                                var certPubKey = cert.GetPublicKey();
                                if (originatorPublicKey != null && !originatorPublicKey.SequenceEqual(certPubKey)) {
                                    throw new InvalidOperationException("Multiple certificates matching originator with differing public keys");
                                }
                                originatorPublicKey = certPubKey;
                            }
                        }
                    }

                    for (var si = 0; si < recipientNative.cRecipientEncryptedKeys; ++si) {
                        recipients.AddRange(new CryptMsgRecipientKeyAgree(buffer, i, recipientInfo.pRecipientInfo, si, originatorPublicKey)
                            .WithMatchingRecipient(availableCerts, preserveRecipientWithoutCertificate:withoutCerts));
                    }
                }
            }

            return recipients;
        }

        private static IReadOnlyList<X509Certificate2> GetEnvelopedCmsCerts(CryptMsgHandle cryptMsgHandle) {
            var certificates = new List<X509Certificate2>();
            
            uint numCerts = 0;
            int numCertsSize = sizeof(uint);
            
            PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgGetParamDword(
                cryptMsgHandle, CryptMsgParamType.CMSG_CERT_COUNT_PARAM, 0, ref numCerts, ref numCertsSize));

            for (uint i = 0; i < numCerts; ++i) {
                byte[] certData = Array.Empty<byte>();
                int certDataSize = certData.Length;
                
                PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(
                    cryptMsgHandle, CryptMsgParamType.CMSG_CERT_PARAM, i, certData, ref certDataSize),
                    r => r.Result || r.Win32ErrorCode == (int)CryptoResult.ERROR_MORE_DATA);


                certData = new byte[certDataSize];
                PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(
                    cryptMsgHandle, CryptMsgParamType.CMSG_CERT_PARAM, i, certData, ref certDataSize));

                certificates.Add(new X509Certificate2(certData));
            }

            return certificates.AsReadOnly();
        }
        
        private static CryptMsgHandle DecodeEnvelopedCmsImpl(byte[] encodedEnvelopedCms) {
            if (encodedEnvelopedCms == null) {
                throw new ArgumentNullException("encodedEnvelopedCms");
            }

            var msgHandle = PinvokeUtil.DoPinvokeWithException(
                () => NativeCryptMsgPinvoke.CryptMsgOpenToDecode(
                    CryptEncodingTypeFlags.X509_ASN_ENCODING | CryptEncodingTypeFlags.PKCS_7_ASN_ENCODING,
                    CryptMsgFlags.None, CryptMsgType.RetrieveTypeFromHeader,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero),
                r => r.Result != null && !r.Result.IsInvalid);

            PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgUpdate(msgHandle, encodedEnvelopedCms,
                (uint) encodedEnvelopedCms.Length, true));

            uint msgTypeRaw = 0;
            int msgTypeSize = Marshal.SizeOf<uint>();
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgGetParamDword(msgHandle, CryptMsgParamType.CMSG_TYPE_PARAM, 0, ref msgTypeRaw,
                    ref msgTypeSize));
            if (msgTypeRaw != (uint) CryptMsgType.CMSG_ENVELOPED) {
                throw new ArgumentException("No valid enveloped cms message.", "encodedEnvelopedCms");
            }

            return msgHandle;
        }

        private static PortableProtectedBinary GetCryptMsgContent(CryptMsgHandle msgHandle) {
            byte[] content = null;
            int contentSize = 0;
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0,
                    content, ref contentSize));
            
            content = new byte[contentSize];
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0,
                    content, ref contentSize));

            if (content.Length != contentSize) {
                Array.Clear(content, 0, content.Length);
                throw new Exception("failed to decrypt message.");
            }
            
            return PortableProtectedBinary.Move(content);
        }

        private static PortableProtectedBinary DecryptCryptMsgKeyTransRecipient(CryptMsgHandle msgHandle, NcryptOrContextHandle nCryptKey, int recipientIndex) {
            var para = new CmsgCtrlDecryptPara(nCryptKey, recipientIndex);
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgControlDecrypt(
                    msgHandle, CryptMsgControlFlags.None, CryptMsgControlType.CMSG_CTRL_DECRYPT, ref para),
                r => CryptoExceptionFactory.forErrorCode(r.Win32ErrorCode));

            return GetCryptMsgContent(msgHandle);
        }
        
        private static PortableProtectedBinary DecryptCryptMsgKeyAgreeRecipient(CryptMsgHandle msgHandle, NcryptOrContextHandle nCryptKey, CryptMsgRecipientKeyAgree keyAgreeRecipient) {
            using (var originatorPublicKeyDataHandle = new HGlobalHandle(keyAgreeRecipient.OriginatorPublicKey)) {
                var para = new CmsgCtrlKeyAgreeDecryptPara(nCryptKey, keyAgreeRecipient, new CryptBitBlob() {
                    cbData = (uint)keyAgreeRecipient.OriginatorPublicKey.Count, pbData = originatorPublicKeyDataHandle.DangerousGetHandle(), cUnusedBits = 0
                });
                PinvokeUtil.DoPinvokeWithException(() =>
                        NativeCryptMsgPinvoke.CryptMsgControlDecryptKeyAgree(
                            msgHandle, CryptMsgControlFlags.None, CryptMsgControlType.CMSG_CTRL_KEY_AGREE_DECRYPT, ref para),
                    r => CryptoExceptionFactory.forErrorCode(r.Win32ErrorCode));

                return GetCryptMsgContent(msgHandle);
            }
        }

        private class CmsRecipientInfo {
            public readonly X509Certificate2 Certificate;
            public readonly byte[] KeyId;
            public readonly bool IsKeyTrans;

            public CmsRecipientInfo(X509Certificate2 certificate, byte[] keyId, bool isKeyTrans) {
                this.Certificate = certificate;
                this.KeyId = keyId;
                this.IsKeyTrans = isKeyTrans;
            }
        }
        private class CmsRecipientCollectionInfo {

            public readonly int NativeSize;
            public readonly IReadOnlyList<CmsRecipientInfo> Recipients;
            public CmsRecipientCollectionInfo(int nativeSize, IReadOnlyList<CmsRecipientInfo> recipients) {
                this.NativeSize = nativeSize;
                this.Recipients = recipients;
            }
        }
        
        private class CmsgRecipientEncodeInfoCollectionHandle : HGlobalHandle {

            private readonly MarshaledStructureHandleCollection itemHandles;

            private readonly int count;
            public CmsgRecipientEncodeInfoCollectionHandle() : base() {}

            public CmsgRecipientEncodeInfoCollectionHandle(IReadOnlyCollection<CmsRecipient> collection) : this(asCmsRecipientCollectionInfo(collection)) { }
            
            public CmsgRecipientEncodeInfoCollectionHandle(CmsRecipientCollectionInfo collection) 
                : base(collection.NativeSize) {
                this.count = collection.Recipients.Count;
                this.itemHandles = new MarshaledStructureHandleCollection();

                // CmsgRecipientEncodeInfo must be stored in continuous memory (array)
                var recipientEncodingAddr = this.DangerousGetHandle();
                
                // referenced structures may be interleaved, section starts after continuous area reserved for CmsgRecipientEncodeInfo 
                var nextAddr = this.DangerousGetHandle() + collection.Recipients.Count * Marshal.SizeOf(typeof(CmsgRecipientEncodeInfo));

                
                foreach (var recipient in collection.Recipients) {
                    var keyAlgorithmParams = recipient.Certificate.GetKeyAlgorithmParameters();
                    var keyAlgorithmParamsAddr = nextAddr;
                    Marshal.Copy(keyAlgorithmParams, 0, keyAlgorithmParamsAddr, keyAlgorithmParams.Length);
                    nextAddr += keyAlgorithmParams.Length;

                    var publicKey = recipient.Certificate.GetPublicKey();
                    var publicKeyAddr = nextAddr;
                    Marshal.Copy(publicKey, 0, publicKeyAddr, publicKey.Length);
                    nextAddr += publicKey.Length;

                    IntPtr keyIdOrIssuerAddr;
                    int keyIdOrIssuerLength;
                    IntPtr certSerialAddr = IntPtr.Zero;
                    int certSerialLength = 0;
                    CertIdChoice certIdChoice;
                    
                    if (recipient.KeyId != null && recipient.KeyId.Length > 0) {
                        certIdChoice = CertIdChoice.CERT_ID_KEY_IDENTIFIER;

                        keyIdOrIssuerAddr = nextAddr;
                        keyIdOrIssuerLength = recipient.KeyId.Length;
                        Marshal.Copy(recipient.KeyId, 0, keyIdOrIssuerAddr, keyIdOrIssuerLength);
                        nextAddr += keyIdOrIssuerLength;
                    } else { // certificate identified by subject + issuer serial number
                        certIdChoice = CertIdChoice.CERT_ID_ISSUER_SERIAL_NUMBER;

                        keyIdOrIssuerAddr = nextAddr;
                        keyIdOrIssuerLength = recipient.Certificate.IssuerName.RawData.Length;
                        Marshal.Copy(recipient.Certificate.IssuerName.RawData, 0, keyIdOrIssuerAddr, keyIdOrIssuerLength);
                        nextAddr += keyIdOrIssuerLength;

                        var serialNumber = recipient.Certificate.GetSerialNumber();
                        certSerialLength = serialNumber.Length;
                        certSerialAddr = nextAddr;
                        Marshal.Copy(serialNumber, 0, certSerialAddr, certSerialLength);
                        nextAddr += certSerialLength;
                    }

                    IntPtr keyTransOrAgreeEncodingAddr;
                    if (recipient.IsKeyTrans) {
                        var keyTransEncoding = new CmsgKeyTransRecipientEncodeInfo() {
                            cbSize = (uint) Marshal.SizeOf(typeof(CmsgKeyTransRecipientEncodeInfo)),
                            KeyEncryptionAlgorithm = {
                                pszObjId = recipient.Certificate.GetKeyAlgorithm(),
                                Parameters = {
                                    cbData = (uint)keyAlgorithmParams.Length,
                                    pbData = keyAlgorithmParamsAddr
                                }
                            },
                            pvKeyEncryptionAuxInfo = IntPtr.Zero,
                            hCryptProv = IntPtr.Zero,
                            RecipientPublicKey = {
                                cbData = (uint)publicKey.Length,
                                pbData = publicKeyAddr,
                                cUnusedBits = 0
                            },
                            RecipientId = {
                                dwIdChoice = certIdChoice,
                                IssuerOrKeyIdOrHashId = {
                                    cbData = (uint) keyIdOrIssuerLength,
                                    pbData = keyIdOrIssuerAddr
                                },
                                IssuerSerialNumber = {
                                    cbData = (uint) certSerialLength,
                                    pbData = certSerialAddr
                                }
                            }
                        };
                        
                        keyTransOrAgreeEncodingAddr = nextAddr;
                        Marshal.StructureToPtr(keyTransEncoding, keyTransOrAgreeEncodingAddr, false);
                        this.itemHandles.AddStructure<CmsgKeyTransRecipientEncodeInfo>(keyTransOrAgreeEncodingAddr);
                        nextAddr += Marshal.SizeOf<CmsgKeyTransRecipientEncodeInfo>();
                    } else {
                        var ephemeralAlgorithm = new CryptAlgorithmIdentifier() {
                            pszObjId = recipient.Certificate.GetKeyAlgorithm(),
                            Parameters = {
                                cbData = (uint) keyAlgorithmParams.Length,
                                pbData = keyAlgorithmParamsAddr
                            }
                        };
                        var ephemeralAlgorithmAddr = nextAddr;
                        Marshal.StructureToPtr(ephemeralAlgorithm, ephemeralAlgorithmAddr, false);
                        this.itemHandles.AddStructure<CryptAlgorithmIdentifier>(ephemeralAlgorithmAddr);
                        nextAddr += Marshal.SizeOf<CryptAlgorithmIdentifier>();

                        var recipientEncryptedKeyInfo = new CmsgRecipientEncryptedKeyEncodeInfo() {
                            cbSize = (uint) Marshal.SizeOf<CmsgRecipientEncryptedKeyEncodeInfo>(),
                            RecipientPublicKey = {
                                cbData = (uint) publicKey.Length,
                                pbData = publicKeyAddr,
                                cUnusedBits = 0
                            },
                            RecipientId = {
                                dwIdChoice = certIdChoice,
                                IssuerOrKeyIdOrHashId = {
                                    cbData = (uint) keyIdOrIssuerLength,
                                    pbData = keyIdOrIssuerAddr
                                },
                                IssuerSerialNumber = {
                                    cbData = (uint) certSerialLength,
                                    pbData = certSerialAddr
                                }
                            },
                            Date = recipient.Certificate.NotBefore.ToFileTime(),
                            pOtherAttr = IntPtr.Zero
                        };
                        var recipientEncryptedKeyInfoAddr = nextAddr;
                        Marshal.StructureToPtr(recipientEncryptedKeyInfo, recipientEncryptedKeyInfoAddr, false);
                        this.itemHandles.AddStructure<CmsgRecipientEncryptedKeyEncodeInfo>(recipientEncryptedKeyInfoAddr);
                        nextAddr += Marshal.SizeOf<CmsgRecipientEncryptedKeyEncodeInfo>();
                        
                        var recipientEncryptedKeyInfoArrayAddr = nextAddr;
                        Marshal.WriteIntPtr(recipientEncryptedKeyInfoArrayAddr, recipientEncryptedKeyInfoAddr);
                        nextAddr += IntPtr.Size;
                        
                        var keyAgreeEncoding = new CmsgKeyAgreeRecipientEncodeInfo() {
                            cbSize = (uint)Marshal.SizeOf<CmsgKeyAgreeRecipientEncodeInfo>(),
                            keyEncryptionAlgorithm = {
                                pszObjId = determineKeyAgreeKeyEncryptionAlgorithm(recipient.Certificate),
                                Parameters = {
                                    cbData = 0,
                                    pbData = IntPtr.Zero
                                }
                            },
                            pvKeyEncryptionAuxInfo = IntPtr.Zero,
                            keyWrapAlgorithm = {
                                pszObjId = KnownOids.AlgAesKeyWrap256,
                                Parameters = {
                                    cbData = 0,
                                    pbData = IntPtr.Zero
                                }
                            },
                            pvKeyWrapAuxInfo = IntPtr.Zero,
                            hCryptProv = IntPtr.Zero,
                            dwKeySpec = 0,
                            dwKeyChoice = CmsgKeyAgreeKeyChoice.CMSG_KEY_AGREE_EPHEMERAL_KEY_CHOICE,
                            pEphemeralAlgorithm = ephemeralAlgorithmAddr,
                            UserKeyingMaterial = {
                                cbData = 0,
                                pbData = IntPtr.Zero,
                            },
                            cRecipientEncryptedKeys = 1,
                            rgpRecipientEncryptedKeys = recipientEncryptedKeyInfoArrayAddr
                        };
                        
                        keyTransOrAgreeEncodingAddr = nextAddr;
                        Marshal.StructureToPtr(keyAgreeEncoding, keyTransOrAgreeEncodingAddr, false);
                        this.itemHandles.AddStructure<CmsgKeyAgreeRecipientEncodeInfo>(keyTransOrAgreeEncodingAddr);
                        nextAddr += Marshal.SizeOf<CmsgKeyAgreeRecipientEncodeInfo>();
                    }
                    
                    var recipientEncoding = new CmsgRecipientEncodeInfo() {
                        dwRecipientChoice = recipient.IsKeyTrans ? CryptMsgRecipientChoice.CMSG_KEY_TRANS_RECIPIENT : CryptMsgRecipientChoice.CMSG_KEY_AGREE_RECIPIENT,
                        pCmsRecipientEncodeInfo = keyTransOrAgreeEncodingAddr
                    };
                    
                    Marshal.StructureToPtr(recipientEncoding, recipientEncodingAddr, false);
                    this.itemHandles.AddStructure<CmsgRecipientEncodeInfo>(recipientEncodingAddr);
                    recipientEncodingAddr += Marshal.SizeOf<CmsgRecipientEncodeInfo>();
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

            private static string determineKeyAgreeKeyEncryptionAlgorithm(X509Certificate2 certificate) {
                var publicKeyTypeName = certificate.PublicKey.Oid.FriendlyName.ToLowerInvariant();
                if (publicKeyTypeName.Contains("ecc")) { // RFC5753                                          
                    var keyBits = GetPublicKeyLengthBits(certificate);
                    return KnownOids.GetAlgKeyAgreeDhSinglePassStdParamsSha(keyBits);
                }
                if (publicKeyTypeName.Contains("rsa")) { //RFC3370, section 4.1.1
                    return KnownOids.AlgEsdhSmimeRsa;
                }
                throw new NotSupportedException("Unsupported public key type: " + publicKeyTypeName + " (OID " + certificate.PublicKey.Oid.Value + ")");
            }

            private static CmsRecipientCollectionInfo asCmsRecipientCollectionInfo(IReadOnlyCollection<CmsRecipient> collection) {
                var recipients = new List<CmsRecipientInfo>(collection.Count);
                var totalSize = collection.Count * Marshal.SizeOf<CmsgRecipientEncodeInfo>();
                foreach (var recipient in collection) {
                    byte[] keyId = null;
                    var canEncrypt = IsEncryptionSupported(recipient.Certificate);
                    
                    // CmsgKeyAgreeRecipientEncodeInfo.KeyEncryptionAlgorithm.Parameters
                    // CmsgKeyAgreeRecipientEncodeInfo.pEphemeralAlgorithm.Parameters
                    totalSize += recipient.Certificate.GetKeyAlgorithmParameters().Length;
                    
                    // CmsgKeyTransRecipientEncodeInfo.RecipientPublicKey
                    // CmsgKeyAgreeRecipientEncodeInfo.rgpRecipientEncryptedKeys[0].RecipientPublicKey
                    totalSize += recipient.Certificate.GetPublicKey().Length;
                    
                    // CmsgKeyTransRecipientEncodeInfo.RecipientId
                    // CmsgKeyAgreeRecipientEncodeInfo.rgpRecipientEncryptedKeys[0].RecipientId
                    var subjectIdentifierExtension = recipient.Certificate.GetSubjectKeyIdentifierExtension();
                    if (recipient.RecipientIdentifierType == SubjectIdentifierType.SubjectKeyIdentifier
                        && subjectIdentifierExtension     != null) {
                        keyId = subjectIdentifierExtension.RawData;
                        totalSize += keyId.Length;
                    } else {
                        totalSize += recipient.Certificate.IssuerName.RawData.Length;
                        totalSize += recipient.Certificate.GetSerialNumber().Length;
                    }

                    if (canEncrypt) {
                        totalSize += Marshal.SizeOf<CmsgKeyTransRecipientEncodeInfo>();
                    } else {
                        totalSize += Marshal.SizeOf<CmsgKeyAgreeRecipientEncodeInfo>();
                        
                        // CmsgKeyAgreeRecipientEncodeInfo.KeyEncryptionAlgorithm without parameters
                        // CmsgKeyAgreeRecipientEncodeInfo.KeyWrapAlgorithm without parameters!
                        
                        // CmsgKeyAgreeRecipientEncodeInfo.pEphemeralAlgorithm
                        totalSize += Marshal.SizeOf<CryptAlgorithmIdentifier>();
                        // Common: CmsgKeyAgreeRecipientEncodeInfo.pEphemeralAlgorithm.Parameters
                        
                        // Empty: CmsgKeyAgreeRecipientEncodeInfo.UserKeyingMaterial
                        
                        // CmsgKeyAgreeRecipientEncodeInfo.rgpRecipientEncryptedKeys
                        totalSize += IntPtr.Size;
                        totalSize += Marshal.SizeOf<CmsgRecipientEncryptedKeyEncodeInfo>();
                        // Common: CmsgKeyAgreeRecipientEncodeInfo.rgpRecipientEncryptedKeys[0].RecipientId
                        // Common: CmsgKeyAgreeRecipientEncodeInfo.rgpRecipientEncryptedKeys[0].RecipientPublicKey
                        // Empty: CmsgKeyAgreeRecipientEncodeInfo.rgpRecipientEncryptedKeys[0].pOtherAttr
                    }
                    
                    recipients.Add(new CmsRecipientInfo(recipient.Certificate, keyId, canEncrypt));
                }
                return new CmsRecipientCollectionInfo(totalSize, recipients.AsReadOnly());
            }
        }

        private class CmsgEnvelopedEncodeInfoHandle : SafeHandleMinusOneIsInvalid {

            private readonly CmsgRecipientEncodeInfoCollectionHandle recipientsHandle;
            private readonly CryptDataBlobListHandle certificatesHandle;
            
            public CmsgEnvelopedEncodeInfoHandle() : base(true) {}
            
            public CmsgEnvelopedEncodeInfoHandle(CmsRecipientCollection recipients, string contentEncryptionOid, CryptographicAttributeObjectCollection unprotectedAttributes) 
                : this(recipients.Cast<CmsRecipient>().ToList(), contentEncryptionOid, unprotectedAttributes) {}

            public CmsgEnvelopedEncodeInfoHandle(IEnumerable<CmsRecipient> recipients, string contentEncryptionOid, CryptographicAttributeObjectCollection unprotectedAttributes)
                : base(true) {

                if (unprotectedAttributes != null && unprotectedAttributes.Count != 0) {
                    throw new NotSupportedException("Unprotected attributes not yet supported");
                }
                
                var recipientsCollection = recipients as IReadOnlyCollection<CmsRecipient> ?? recipients.ToList();
                this.recipientsHandle = new CmsgRecipientEncodeInfoCollectionHandle(recipientsCollection);
                this.certificatesHandle = new CryptDataBlobListHandle(recipientsCollection
                          .Select(r => r.Certificate.Export(X509ContentType.Cert))
                          .DistinctByStructure()
                          .ToList());
                    
                var encodeInfo = new CmsgEnvelopedEncodeInfo() {
                    cbSize = (uint)Marshal.SizeOf<CmsgEnvelopedEncodeInfo>(),
                    hCryptProv = IntPtr.Zero,
                    ContentEncryptionAlgorithm = {
                        pszObjId = contentEncryptionOid,
                        Parameters = {
                            cbData = 0,
                            pbData = IntPtr.Zero,
                        }
                    },
                    pvEncryptionAuxInfo = IntPtr.Zero,
                    cRecipients = (uint)this.recipientsHandle.Count,
                    rgpRecipients = IntPtr.Zero,
                    rgCmsRecipients = this.recipientsHandle.DangerousGetHandle(),
                    cCertEncoded = this.certificatesHandle.Count,
                    rgCertEncoded = this.certificatesHandle.DangerousGetHandle(),
                    cAttrCertEncoded = 0,
                    rgAttrCertEncoded = IntPtr.Zero,
                    cUnprotectedAttr = 0,
                    rgUnprotectedAttr = IntPtr.Zero // Fixme: copy given unprotectedAttributes
                };
                
                this.SetHandle(Marshal.AllocHGlobal(Marshal.SizeOf<CmsgEnvelopedEncodeInfo>()));
                Marshal.StructureToPtr(encodeInfo, this.handle, false);
            }

            protected override bool ReleaseHandle() {
                this.recipientsHandle.DangerousRelease();
                this.certificatesHandle.DangerousRelease();
                
                Marshal.DestroyStructure<CmsgEnvelopedEncodeInfo>(this.handle);
                Marshal.FreeHGlobal(this.handle);
                
                this.SetHandleAsInvalid();
                return true;
            }
        }
    }
}