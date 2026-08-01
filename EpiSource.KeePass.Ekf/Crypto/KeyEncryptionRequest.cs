using System.Collections.Generic;

using EpiSource.KeePass.Ekf.Plugin;
using EpiSource.KeePass.Ekf.Util;

using KeePassLib.Keys;
using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
    public class KeyEncryptionRequest {
        private readonly PortableProtectedBinary plaintextKey;
        private readonly KcpKeyFile virtualKeyFile;
        private readonly IList<IKeyPair> authorizedKeyPairs;
        
        public KeyEncryptionRequest(PortableProtectedBinary plaintextKey, IEnumerable<IKeyPair> authorizedKeyPairs) {
            this.plaintextKey = plaintextKey;
            this.virtualKeyFile = plaintextKey.ToVirtualKeyFile();
            this.authorizedKeyPairs = new List<IKeyPair>(authorizedKeyPairs).AsReadOnly();
        }

        public KeyEncryptionRequest(ProtectedBinary plaintextKey, IEnumerable<IKeyPair> authorizedKeyPairs)
            : this(plaintextKey.ToPortable(), authorizedKeyPairs) { }

        /// <summary>
        /// The raw key to be stored in an encrypted key file.
        /// </summary>
        /// <returns>
        /// A copy of the raw key array.
        /// </returns>
        public PortableProtectedBinary PlaintextKey {
            get { return this.plaintextKey; }
        }

        /// <summary>
        /// The <see cref="PlaintextKey"/> wrapped in a (virtual) <see cref="KcpKeyFile"/>:
        /// as if the plaintext key data was read from a key file by KeePass itself.
        /// </summary>
        public KcpKeyFile VirtualKeyFile {
            get { return this.virtualKeyFile; }
        }

        public IList<IKeyPair> AuthorizedKeyPairs {
            get { return this.authorizedKeyPairs; }
        }

        public EncryptedKeyFile Encrypt(bool strictRfc5753) {
            return new DecryptedKeyFile(this.AuthorizedKeyPairs, this.PlaintextKey).Encrypt(strictRfc5753);
        }

    }
}