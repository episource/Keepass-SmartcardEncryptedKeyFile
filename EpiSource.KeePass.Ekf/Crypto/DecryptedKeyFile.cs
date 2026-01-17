using System;
using System.Collections.Generic;

using EpiSource.KeePass.Ekf.Util;

namespace EpiSource.KeePass.Ekf.Crypto {
    /// <remarks>
    /// This class can be serialized. The serialized data is encrypted using a session key bound to the current user
    /// session. This means deserialization is only requires the same session to be active that was used for
    /// serialization. DecryptedKeyFile should be serialized for remoting purposes, only. Use EncryptedKeyFile to
    /// persist key data.
    /// </remarks>
    [Serializable]
    public sealed class DecryptedKeyFile : LimitedAccessKeyFile {
        
        private readonly PortableProtectedBinary protectedPlaintextKey;
        
        internal DecryptedKeyFile(IEnumerable<IKeyPair> authorization, PortableProtectedBinary protectedPlaintextKey)
            : base(authorization) {
            this.protectedPlaintextKey = protectedPlaintextKey;
        }
        
        /// <summary>
        /// The raw key as stored in the encrypted key file.
        /// </summary>
        /// <returns>
        /// A copy of the raw key array.
        /// </returns>
        public PortableProtectedBinary PlaintextKey {
            get { return this.protectedPlaintextKey; }
        }

        public EncryptedKeyFile Encrypt(bool strictRfc5753=true) {
            return new EncryptedKeyFile(this, strictRfc5753);
        }
    }
}