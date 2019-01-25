using System.Collections.Generic;

using Episource.KeePass.EKF.Crypto;

using KeePassLib.Security;

namespace Episource.KeePass.EKF.Keys {
    public class RandomKeyDataStore : IKeyDataStore {

        public RandomKeyDataStore() : this(string.Empty) {
            
        }
        public RandomKeyDataStore(IEnumerable<byte> entropy) {
            this.KeyData = new RandomKeyGenerator().Shuffle(entropy);
        }

        public RandomKeyDataStore(string entropy) {
            this.KeyData = new RandomKeyGenerator().Shuffle(entropy);
        }

        public ProtectedBinary KeyData { get; private set; }

        public bool IsRandom {
            get { return true; }
        }
    }
}