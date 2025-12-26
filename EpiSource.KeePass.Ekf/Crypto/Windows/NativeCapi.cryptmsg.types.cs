using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using EpiSource.KeePass.Ekf.Util;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {

        private abstract class CryptMsgRecipient {
            public CryptMsgRecipient(SafeHandle nativeHandle, int recipientIndex, X509Certificate2 recipientCert) {
                this.NativeHandle = nativeHandle;
                this.RecipientIndex = recipientIndex;
                this.RecipientCert = recipientCert;
            }
            
            // keep handle to native data: referenced native structures (IntPtr members) valid until this is freed.
            protected readonly SafeHandle NativeHandle;
            public readonly int RecipientIndex;
            public readonly X509Certificate2 RecipientCert;

            public abstract CertId RecipientCertId {
                get;
            }

            public IEnumerable<CryptMsgRecipient> WithMatchingRecipient(IEnumerable<X509Certificate2> availableCerts, bool preserveRecipientWithoutCertificate=false) {
                if (this.RecipientCert != null) {
                    throw new InvalidOperationException("Recipient Cert already set");
                }

                var recipients = availableCerts
                         .Where(c => this.RecipientCertId.IsMatchingCert(c))
                         .Select(this.SetRecipientCert);

                return preserveRecipientWithoutCertificate ? recipients.DefaultIfEmpty(this) : recipients;
            }
            
            public abstract CryptMsgRecipient SetRecipientCert(X509Certificate2 recipientCert);
        }

        private class CryptMsgRecipientKeyAgree : CryptMsgRecipient {
            public CryptMsgRecipientKeyAgree(SafeHandle nativeHandle, int recipientIndex, IntPtr recipientInfoPtrUnsafe, int subIndex, IReadOnlyList<byte> originatorPublicKey, X509Certificate2 recipientCert = null) 
                        : base(nativeHandle, recipientIndex, recipientCert) {
                this.RecipientInfoPtrUnsafe = recipientInfoPtrUnsafe;
                this.RecipientInfo = Marshal.PtrToStructure<CmsgKeyAgreeRecipientInfo>(recipientInfoPtrUnsafe);
                
                if (subIndex >= this.RecipientInfo.cRecipientEncryptedKeys) {
                    throw new ArgumentOutOfRangeException("subIndex", subIndex, "subIndex >= " + this.RecipientInfo.cRecipientEncryptedKeys);
                }

                this.SubIndex = subIndex;
                this.RecipientEncryptedKeyInfoPtrUnsafe = Marshal.ReadIntPtr(this.RecipientInfo.rpgRecipientEncryptedKeys + subIndex * Marshal.SizeOf<IntPtr>());
                this.RecipientEncryptedKeyInfo = Marshal.PtrToStructure<CmsgRecipientEncryptedKeyInfo>(this.RecipientEncryptedKeyInfoPtrUnsafe);

                if (originatorPublicKey != null) {
                    this.OriginatorPublicKey =  originatorPublicKey.ToList().AsReadOnly();
                } else if (this.RecipientInfo.dwOriginatorChoice == CmsgKeyAgreeOriginator.CMSG_KEY_AGREE_ORIGINATOR_PUBLIC_KEY) {
                    this.OriginatorPublicKey = new ReadOnlyCollection<byte>(this.RecipientInfo.Originator.PublicKey.PublicKey.CopyToByteArray());
                } else {
                    throw new ArgumentException("Originator Public Key missing");
                }
            }
            
            public readonly IntPtr RecipientInfoPtrUnsafe; // CmsgKeyAgreeRecipientInfo
            public readonly CmsgKeyAgreeRecipientInfo RecipientInfo;
            
            public readonly int SubIndex;
            public readonly IntPtr RecipientEncryptedKeyInfoPtrUnsafe; // CmsgRecipientEncryptedKeyInfo
            public readonly CmsgRecipientEncryptedKeyInfo RecipientEncryptedKeyInfo;

            public readonly IReadOnlyList<byte> OriginatorPublicKey;
            
            public override CertId RecipientCertId {
                get {
                    return this.RecipientEncryptedKeyInfo.RecipientId;
                }
            }
            public override CryptMsgRecipient SetRecipientCert(X509Certificate2 recipientCert) {
                if (recipientCert != null && !this.RecipientCertId.IsMatchingCert(recipientCert)) {
                    throw new ArgumentException("given certificate does not match the current recipient");
                }
                return new CryptMsgRecipientKeyAgree(this.NativeHandle, this.RecipientIndex, this.RecipientInfoPtrUnsafe, this.SubIndex, this.OriginatorPublicKey, recipientCert);
            }

            public CryptMsgRecipientKeyAgree SetOriginatorPublicKey(IReadOnlyList<byte> publicKey) {
                if (this.OriginatorPublicKey != null) {
                    throw new InvalidOperationException("already set");
                }
                return new CryptMsgRecipientKeyAgree(this.NativeHandle, this.RecipientIndex, this.RecipientInfoPtrUnsafe, this.SubIndex, publicKey, this.RecipientCert);
            }
            
        }

        private class CryptMsgRecipientKeyTrans : CryptMsgRecipient {
            
            public CryptMsgRecipientKeyTrans(SafeHandle nativeHandle, int recipientIndex, IntPtr recipientInfoPtrUnsafe, X509Certificate2 recipientCert = null) 
                : base(nativeHandle, recipientIndex, recipientCert) {
                this.RecipientInfoPtrUnsafe = recipientInfoPtrUnsafe;
                this.RecipientInfo = Marshal.PtrToStructure<CmsgKeyTransRecipientInfo>(recipientInfoPtrUnsafe);
            }
            
            public readonly IntPtr RecipientInfoPtrUnsafe; // CmsgKeyTransRecipientInfo
            public readonly CmsgKeyTransRecipientInfo RecipientInfo;
            
            public override CertId RecipientCertId {
                get {
                    return this.RecipientInfo.RecipientId;
                }
            }
            public override CryptMsgRecipient SetRecipientCert(X509Certificate2 recipientCert) {
                if (recipientCert != null && !this.RecipientCertId.IsMatchingCert(recipientCert)) {
                    throw new ArgumentException("given certificate does not match the current recipient");
                }
                
                return new CryptMsgRecipientKeyTrans(this.NativeHandle, this.RecipientIndex, this.RecipientInfoPtrUnsafe, recipientCert);
            }
        }
    }
}