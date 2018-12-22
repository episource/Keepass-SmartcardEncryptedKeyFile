using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using KeePassLib.Security;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace Episource.KeePass.EKF.Crypto {
    public sealed class EncryptedKeyFile : LimitedAccessKeyFile {
        private readonly Oid oidContentData =
            Oid.FromOidValue(oidValue: "1.2.840.113549.1.7.1", group: OidGroup.ExtensionOrAttribute);

        private readonly AlgorithmIdentifier algorithmAes256Cbc =
            new AlgorithmIdentifier(
                Oid.FromOidValue(oidValue: "2.16.840.1.101.3.4.1.42", group: OidGroup.EncryptionAlgorithm),
                keyLength: 256);
        
        // invariant: always encrypted!
        private readonly byte[] encryptedKeyStore;

        public EncryptedKeyFile(DecryptedKeyFile plaintext)
            : base(plaintext.Authorization) {
            if (plaintext == null) {
                throw new ArgumentNullException("plaintext");
            }
            
            var content = new ContentInfo(this.oidContentData, plaintext.PlaintextKey);
            var store = new EnvelopedCms(content, this.algorithmAes256Cbc);
            var recipients = new CmsRecipientCollection();

            foreach (var keyPair in plaintext.Authorization) {
                store.Certificates.Add(keyPair.Certificate);
                recipients.Add(new CmsRecipient(keyPair.Certificate));
            }

            store.Encrypt(recipients);
            this.encryptedKeyStore = store.Encode();
        }

        private EncryptedKeyFile(IEnumerable<IKeyPair> authorization, byte[] encryptedKeyStore) 
            : base(authorization) {
            this.encryptedKeyStore = encryptedKeyStore;
        }

        public static EncryptedKeyFile Decode(byte[] encryptedKeyStore) {
            if (encryptedKeyStore == null) {
                throw new ArgumentNullException("encryptedKeyStore");
            }
            
            var store = new EnvelopedCms();
            store.Decode(encryptedKeyStore);

            var localKeyPairs = RsaSmartcardKeyPairs.GetAllKeyPairs().ToDictionary(c => c.Certificate.Thumbprint);
            var authorization = store.Certificates
                                     .Cast<X509Certificate2>()
                                     .Select(c =>
                                         localKeyPairs.ContainsKey(c.Thumbprint)
                                             ? localKeyPairs[c.Thumbprint]
                                             : RSACryptoServiceProviderKeyPair.FromX509CertificateOrNull(c))
                                     .Where(c => c != null);

            return new EncryptedKeyFile(authorization, encryptedKeyStore);
        }

        public static EncryptedKeyFile Read(Stream source) {
            var buffer = new MemoryStream();
            MemUtil.CopyStream(source, buffer);
            
            return Decode(buffer.ToArray());
        }

        public DecryptedKeyFile Decrypt() {
            var store = new EnvelopedCms();
            store.Decode(this.encryptedKeyStore);
            store.Decrypt();
            
            return new DecryptedKeyFile(this.Authorization, store.ContentInfo.Content);
        }

        public byte[] Encode() {
            return this.encryptedKeyStore;
        }
        
        public void Write(Stream target) {
            target.Write(this.encryptedKeyStore, 0, this.encryptedKeyStore.Length);
        }
    }
}