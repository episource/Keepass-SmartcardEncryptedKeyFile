using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using KeePassLib.Utility;

namespace Episource.KeePass.EKF.Crypto {
    [Serializable]
    public sealed class EncryptedKeyFile : LimitedAccessKeyFile {
        private static readonly Oid oidContentData =
            Oid.FromOidValue("1.2.840.113549.1.7.1", OidGroup.ExtensionOrAttribute);

        private static readonly AlgorithmIdentifier algorithmAes256Cbc =
            new AlgorithmIdentifier(
                Oid.FromOidValue("2.16.840.1.101.3.4.1.42", OidGroup.EncryptionAlgorithm),
                256);
        
        // invariant: always encrypted!
        private readonly byte[] encryptedKeyStore;

        public EncryptedKeyFile(DecryptedKeyFile plaintext)
            : base(plaintext.Authorization) {
            if (plaintext == null) {
                throw new ArgumentNullException("plaintext");
            }
            
            var content = new ContentInfo(oidContentData, plaintext.PlaintextKey);
            var store = new EnvelopedCms(content, algorithmAes256Cbc);
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

            var localKeyPairs = RSASmartcardKeyPairs.GetAllKeyPairs().ToDictionary(c => c.Certificate.Thumbprint);
            var authorization = store.Certificates
                                     .Cast<X509Certificate2>()
                                     .Select(c => // ReSharper disable once AssignNullToNotNullAttribute
                                         localKeyPairs.ContainsKey(c.Thumbprint)
                                             ? localKeyPairs[c.Thumbprint]
                                             : RSACryptoServiceProviderKeyPair.FromX509CertificateAssumeCspOrNull(c))
                                     .Where(c => c != null);

            return new EncryptedKeyFile(authorization, encryptedKeyStore);
        }

        public static EncryptedKeyFile Read(Stream source) {
            var buffer = new MemoryStream();
            MemUtil.CopyStream(source, buffer);
            
            return Decode(buffer.ToArray());
        }

        /// <summary>
        /// Decrypt the key file using one of the authorized smartcards.
        /// This operation requires the user to provide an authorized smartcard and unlock it. How the user needs to
        /// unlock the smartcard depends on the smartcard and reader that are used. Usually a pin must be enter in
        /// a software prompt or at the reader. Some smartcards require a button to be pressed, as well.
        /// The operation blocks until the user has successfully unlocked the smartcard or the operation times out. 
        /// </summary>
        /// <returns>A <see cref="DecryptedKeyFile">DecryptedKeyFile</see>.</returns>
        /// <exception cref="CryptographicException">Failed to decrypt the key file. E.g. because the operation timed
        /// out or no authorized smartcard was found.</exception>
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