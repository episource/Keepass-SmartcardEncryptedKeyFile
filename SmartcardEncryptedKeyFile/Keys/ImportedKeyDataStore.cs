using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Threading;

using KeePassLib.Security;

namespace Episource.KeePass.EKF.Keys {
    public class ImportedKeyDataStore : IKeyDataStore {

        private readonly string fileName;

        public ImportedKeyDataStore(string filePath) : this(Path.GetFileName(filePath), File.ReadAllBytes(filePath)) {
        }
        public ImportedKeyDataStore(string fileName, byte[] importedKey) : this(fileName, new ProtectedBinary(true, importedKey)) {
        }

        public ImportedKeyDataStore(string fileName, ProtectedBinary importedKey) {
            this.fileName = fileName;
            this.KeyData = importedKey;
        }

        public ProtectedBinary KeyData { get; private set; }

        public bool IsRandom {
            get { return false; }
        }

        public string FileName {
            get { return this.fileName; }
        }
    }
}