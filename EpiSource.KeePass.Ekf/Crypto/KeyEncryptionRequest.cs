using System.Collections.Generic;

using EpiSource.KeePass.Ekf.KeyProvider;

using KeePassLib.Security;
using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.Util {
    public class KeyEncryptionRequest {
        private readonly IOConnectionInfo dbPath;
        private readonly PortableProtectedBinary plaintextKey;
        private readonly IList<IKeyPair> authorizedKeyPairs;
        
        public KeyEncryptionRequest(IOConnectionInfo dbPath, PortableProtectedBinary plaintextKey, IEnumerable<IKeyPair> authorizedKeyPairs) {
            this.dbPath = dbPath.CloneDeep();
            this.plaintextKey = plaintextKey.Clone();
            this.authorizedKeyPairs = new List<IKeyPair>(authorizedKeyPairs).AsReadOnly();
        }

        public KeyEncryptionRequest(IOConnectionInfo dbPath, ProtectedBinary plaintextKey, IEnumerable<IKeyPair> authorizedKeyPairs)
            : this(dbPath, plaintextKey.ToPortable(), authorizedKeyPairs) { }

        public IOConnectionInfo DbPath {
            get { return this.dbPath.CloneDeep(); }
        }

        public IOConnectionInfo EncryptedKeyFilePath {
            get { return this.dbPath.ResolveEncryptedKeyFile(); }
        }
        
        /// <summary>
        /// The raw key to be stored in an encrypted key file.
        /// </summary>
        /// <returns>
        /// A copy of the raw key array.
        /// </returns>
        public PortableProtectedBinary PlaintextKey {
            get { return this.plaintextKey.Clone(); }
        }

        public IList<IKeyPair> AuthorizedKeyPairs {
            get { return this.authorizedKeyPairs; }
        }

        public void WriteEncryptedKeyFile() {
            var encrypted = new DecryptedKeyFile(this.AuthorizedKeyPairs, this.PlaintextKey).Encrypt();
            using (var stream = IOConnection.OpenWrite(this.EncryptedKeyFilePath)) {
                encrypted.Write(stream);
            }
        }
    }
}