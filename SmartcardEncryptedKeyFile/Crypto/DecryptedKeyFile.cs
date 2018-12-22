using System.Collections.Generic;

using KeePassLib.Security;

namespace Episource.KeePass.EKF.Crypto {
    public class DecryptedKeyFile : LimitedAccessKeyFile {
        private readonly ProtectedBinary plaintextKey;
        
        internal DecryptedKeyFile(IEnumerable<IKeyPair> authorization, byte[] plaintextKey) 
            : base(authorization) {
            this.plaintextKey = plaintextKey.Protect();
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