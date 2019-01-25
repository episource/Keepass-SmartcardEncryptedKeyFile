using KeePassLib.Security;

namespace Episource.KeePass.EKF.Keys {
    public class ImportedKeyDataStore : IKeyDataStore {
        public ImportedKeyDataStore(byte[] importedKey) : this(new ProtectedBinary(true, importedKey)) {
        }

        public ImportedKeyDataStore(ProtectedBinary importedKey) {
            this.KeyData = importedKey;
        }

        public ProtectedBinary KeyData { get; private set; }

        public bool IsRandom {
            get { return false; }
        }
    }
}