using KeePassLib.Keys;
using KeePassLib.Security;

namespace Episource.KeePass.EKF.Keys {
    public class LiveKeyDataStore : IKeyDataStore {
        private readonly IUserKey currentKey;

        public LiveKeyDataStore(IUserKey currentKey) {
            this.currentKey = currentKey;
        }

        public ProtectedBinary KeyData {
            get { return this.currentKey.KeyData; }
        }

        public bool IsRandom {
            get { return false; }
        }
    }
}