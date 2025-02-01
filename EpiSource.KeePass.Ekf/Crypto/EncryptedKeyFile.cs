using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto.Windows;

using KeePassLib.Security;
using KeePassLib.Utility;

namespace EpiSource.KeePass.Ekf.Crypto {
    /// <remarks>
    /// Methods block if a busy hardware device is involved.
    /// </remarks>
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

            var content = new ContentInfo(oidContentData, plaintext.PlaintextKey.ReadUnprotected());
            try {
                var store = new EnvelopedCms(content, algorithmAes256Cbc);
                var recipients = new CmsRecipientCollection();

                foreach (var keyPair in plaintext.Authorization) {
                    // embed  list of authorized certificates as originator info
                    // doing so permits re-encryption without having all certificates installed locally
                    store.Certificates.Add(keyPair.Certificate);

                    // recipient list controls which certificates can decrypt the ekf
                    recipients.Add(new CmsRecipient(keyPair.Certificate));
                }

                store.Encrypt(recipients);
                this.encryptedKeyStore = store.Encode();
            } finally {
                Array.Clear(content.Content, 0, content.Content.Length);
            }
        }

        private EncryptedKeyFile(IEnumerable<IKeyPair> authorization, byte[] encryptedKeyStore) 
            : base(authorization) {
            this.encryptedKeyStore = encryptedKeyStore;
        }

        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public static EncryptedKeyFile Decode(byte[] encryptedKeyStore) {
            if (encryptedKeyStore == null) {
                throw new ArgumentNullException("encryptedKeyStore");
            }
            
            var store = new EnvelopedCms();
            store.Decode(encryptedKeyStore);

            // note: GetAllKeyPairs blocks if busy HW is involved.
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

        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public static EncryptedKeyFile Read(Stream source) {
            using (var buffer = new MemoryStream()) {
                MemUtil.CopyStream(source, buffer);

                // note: Decode blocks if busy HW is involved.
                return Decode(buffer.ToArray());
            }
        }

        /// <summary>
        /// Decrypt the key file using one of the authorized smartcards.
        /// This operation requires the user to provide an authorized smartcard and unlock it. How the user needs to
        /// unlock the smartcard depends on the smartcard and reader that are used. Usually a pin must be enter in
        /// a software prompt or at the reader. Some smartcards require a button to be pressed, as well.
        /// The operation blocks until the user has successfully unlocked the smartcard or the operation times out. 
        /// </summary>
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        /// <returns>A <see cref="DecryptedKeyFile">DecryptedKeyFile</see>.</returns>
        /// <param name="contextDescription">Description of the application or operation that is accessing the private key.</param>
        /// <param name="uiOwner">Window that should become owner of any dialog that needs to be shown.</param>
        /// <param name="pin">Pin for unlocking the private key. When given, silent operation is requested.</param>
        /// <returns>A <see cref="DecryptedKeyFile">DecryptedKeyFile</see>.</returns>
        /// <exception cref="CryptographicException">Failed to decrypt the key file. E.g. because the operation timed
        /// out or no authorized smartcard was found.</exception>
        public DecryptedKeyFile Decrypt(string contextDescription = null, IntPtr uiOwner = new IntPtr(), bool alwaysSilent = false, PortableProtectedString pin = null) {
            var decrypted = NativeCapi.DecryptEnvelopedCms(this.encryptedKeyStore, alwaysSilent, contextDescription, uiOwner, pin);
            return new DecryptedKeyFile(this.Authorization, decrypted);
        }

        /// <summary>
        /// Decrypt the key file using the given recipient key information.
        /// This operation requires the user to provide an authorized smartcard and unlock it. How the user needs to
        /// unlock the smartcard depends on the smartcard and reader that are used. Usually a pin must be enter in
        /// a software prompt or at the reader. Some smartcards require a button to be pressed, as well.
        /// The operation blocks until the user has successfully unlocked the smartcard or the operation times out. 
        /// </summary>
        /// <param name="recipientKeyPair">This key pair is used for decryption.</param>
        /// <param name="contextDescription">Description of the application or operation that is accessing the private key.</param>
        /// <param name="uiOwner">Window that should become owner of any dialog that needs to be shown.</param>
        /// <param name="alwaysSilent">Request silent operation, also if no pin is given. Useful to check if the smartcard or key is currently unlocked.</param>
        /// <param name="pin">Pin for unlocking the private key. When given, silent operation is requested.</param>
        /// <returns>A <see cref="DecryptedKeyFile">DecryptedKeyFile</see>.</returns>
        /// <exception cref="CryptographicException">Failed to decrypt the key file. E.g. because the operation timed
        /// out or no authorized smartcard was found.</exception>
        /// <exception cref="ArgumentNullException">The provided key pair is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The provided key pair is not suitable to decrypt the key
        /// file.</exception>
        public DecryptedKeyFile Decrypt(IKeyPair recipientKeyPair, string contextDescription = null, IntPtr uiOwner = new IntPtr(), bool alwaysSilent=false, PortableProtectedString pin = null) {
            if (recipientKeyPair == null) {
                throw new ArgumentNullException("recipientKeyPair");
            }
            if (recipientKeyPair.Certificate == null) {
                throw new ArgumentOutOfRangeException("recipientKeyPair", "recipientKeyPair not ready for decrypt.");
            }

            var decrypted = NativeCapi.DecryptEnvelopedCms(this.encryptedKeyStore, recipientKeyPair, alwaysSilent, contextDescription, uiOwner, pin);
            return new DecryptedKeyFile(this.Authorization, decrypted);
        }

        /// <summary>
        /// Decrypt the key file using the given recipient key information.
        /// This operation requires the user to provide an authorized smartcard and unlock it. How the user needs to
        /// unlock the smartcard depends on the smartcard and reader that are used. Usually a pin must be enter in
        /// a software prompt or at the reader. Some smartcards require a button to be pressed, as well.
        /// The operation blocks until the user has successfully unlocked the smartcard or the operation times out. 
        /// </summary>
        /// <param name="recipientKeyPair">This key pair is used for decryption.</param>
        /// <param name="contextDescription">Description of the application or operation that is accessing the private key.</param>
        /// <param name="uiOwner">Window that should become owner of any dialog that needs to be shown.</param>
        /// <param name="alwaysSilent">Request silent operation, also if no pin is given. Useful to check if the smartcard or key is currently unlocked.</param>
        /// <param name="pin">Pin for unlocking the private key. When given, silent operation is requested.</param>
        /// <returns>A <see cref="DecryptedKeyFile">DecryptedKeyFile</see>.</returns>
        /// <exception cref="CryptographicException">Failed to decrypt the key file. E.g. because the operation timed
        /// out or no authorized smartcard was found.</exception>
        /// <exception cref="ArgumentNullException">The provided key pair is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The provided key pair is not suitable to decrypt the key
        /// file.</exception>
        public DecryptedKeyFile Decrypt(IKeyPair recipientKeyPair, string contextDescription = null, Form uiOwner = null, bool alwaysSilent=false, PortableProtectedString pin = null) {
            if (recipientKeyPair == null) {
                throw new ArgumentNullException("recipientKeyPair");
            }
            if (recipientKeyPair.Certificate == null) {
                throw new ArgumentOutOfRangeException("recipientKeyPair", "recipientKeyPair not ready for decrypt.");
            }

            var decrypted = NativeCapi.DecryptEnvelopedCms(this.encryptedKeyStore, recipientKeyPair, alwaysSilent, contextDescription, uiOwner != null ? uiOwner.Handle : IntPtr.Zero, pin);
            return new DecryptedKeyFile(this.Authorization, decrypted);
        }

        public byte[] Encode() {
            return this.encryptedKeyStore;
        }
        
        public void Write(Stream target) {
            target.Write(this.encryptedKeyStore, 0, this.encryptedKeyStore.Length);
        }
    }
}