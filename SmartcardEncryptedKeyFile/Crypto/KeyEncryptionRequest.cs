using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

using KeePassLib.Security;
using KeePassLib.Serialization;

namespace Episource.KeePass.EKF.Crypto {
    public class KeyEncryptionRequest {
        private readonly IOConnectionInfo dbPath;
        private readonly ProtectedBinary plaintextKey;
        private readonly IList<IKeyPair> authorizedKeyPairs;
        
        public KeyEncryptionRequest(IOConnectionInfo dbPath, byte[] plaintextKey, IEnumerable<IKeyPair> authorizedKeyPairs) {
            this.dbPath = dbPath.CloneDeep();
            this.plaintextKey = plaintextKey.Protect();
            this.authorizedKeyPairs = new List<IKeyPair>(authorizedKeyPairs).AsReadOnly();
        }

        public KeyEncryptionRequest(IOConnectionInfo dbPath, ProtectedBinary plaintextKey, IEnumerable<IKeyPair> authorizedKeyPairs)
            : this(dbPath, plaintextKey.ReadData(), authorizedKeyPairs) { }

        public IOConnectionInfo DbPath {
            get { return this.dbPath.CloneDeep(); }
        }

        public IOConnectionInfo EncryptedKeyFilePath {
            get {
                var path = this.dbPath.CloneDeep();
                path.Path = path.Path + ".ekf";
                return path;
            }
        }
        
        /// <summary>
        /// The raw key to be stored in an encrypted key file.
        /// Important: The returned key is stored in process memory without encryption!
        /// </summary>
        /// <returns>
        /// A copy of the raw key array.
        /// </returns>
        public byte[] PlaintextKey {
            get { return this.plaintextKey.ReadData(); }
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