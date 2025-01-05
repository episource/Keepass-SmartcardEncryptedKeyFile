using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Cryptography;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
    /// <remarks>
    /// This class can be serialized. The serialized data is encrypted using a session key bound to the current user
    /// session. This means deserialization is only requires the same session to be active that was used for
    /// serialization. DecryptedKeyFile should be serialized for remoting purposes, only. Use EncryptedKeyFile to
    /// persist key data.
    /// </remarks>
    [Serializable]
    public sealed class DecryptedKeyFile : LimitedAccessKeyFile, ISerializable {
        
        private readonly ProtectedBinary plaintextKey;
        
        internal DecryptedKeyFile(IEnumerable<IKeyPair> authorization, byte[] plaintextKey) 
            : base(authorization) {
            this.plaintextKey = plaintextKey.Protect();
        }

        private DecryptedKeyFile(SerializationInfo info, StreamingContext context)
            : base((IList<IKeyPair>) info.GetValue("authorization", typeof(IList<IKeyPair>)), true) {

            var keyLength = info.GetInt32("keyLength");
            var protectedKey = (byte[])info.GetValue("protectedKey", typeof(byte[]));
            
            ProtectedMemory.Unprotect(protectedKey, MemoryProtectionScope.SameLogon);
            
            var plaintext = new byte[keyLength];
            Array.Copy(protectedKey, plaintext, keyLength);
            this.plaintextKey = plaintext.Protect();
        }
        
        public void GetObjectData(SerializationInfo info, StreamingContext context) {
            var plaintext = this.PlaintextKey;
            
            const int chunkSize = 16;
            var protectedKeySize = (plaintext.Length + chunkSize - 1) / chunkSize * chunkSize;
            var protectedKey = new byte[protectedKeySize];
            
            Array.Copy(plaintext, protectedKey, plaintext.Length);
            ProtectedMemory.Protect(protectedKey, MemoryProtectionScope.SameLogon);
            
            info.AddValue("authorization", this.Authorization, typeof(IList<IKeyPair>));
            info.AddValue("keyLength", plaintext.Length);
            info.AddValue("protectedKey", protectedKey);
        }
        
        /// <summary>
        /// The raw key as stored in the encrypted key file.
        /// Important: The returned key is stored in process memory without encryption!
        /// </summary>
        /// <returns>
        /// A copy of the raw key array.
        /// </returns>
        public byte[] PlaintextKey {
            get { return this.plaintextKey.ReadData(); }
        }

        public EncryptedKeyFile Encrypt() {
            return new EncryptedKeyFile(this);
        }
    }
}