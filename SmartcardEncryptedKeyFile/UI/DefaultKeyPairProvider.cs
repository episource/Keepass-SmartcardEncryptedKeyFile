using System.Collections.Generic;
using System.Linq;

using Episource.KeePass.Ekf.KeyProvider;
using Episource.KeePass.EKF.Crypto;

using KeePassLib.Serialization;

namespace Episource.KeePass.EKF.UI {
    public class DefaultKeyPairProvider : IKeyPairProvider {
        private readonly ISet<string> authorizedKeys;
        private readonly IDictionary<string, KeyPairModel> knownKeys = new Dictionary<string, KeyPairModel>();
        
        public DefaultKeyPairProvider(IOConnectionInfo dbPath) {
            var ekfPath = dbPath.ResolveEncryptedKeyFile();

            if (IOConnection.FileExists(ekfPath)) {
                using (var stream = IOConnection.OpenRead(ekfPath)) {
                    var ekf = EncryptedKeyFile.Read(stream);
                    
                    this.authorizedKeys = ekf.Authorization
                                          .Select(c => c.Certificate.Thumbprint)
                                          .ToHashSet();
                    this.AddKeys(ekf.Authorization, KeyPairModel.KeyProvider.EkfAuthorizationList);
                }
            } else {
                this.authorizedKeys = new HashSet<string>();
            }
            
            
            // add piv cards last: replace existing keys from other sources (piv is primary provider)
            this.AddKeys(RSASmartcardKeyPairs.GetAllPivKeyPairs(), KeyPairModel.KeyProvider.Piv);
        }

        private void AddKeys(IEnumerable<IKeyPair> keyPairs, KeyPairModel.KeyProvider provider) {
            foreach (var keyPair in keyPairs) {
                var thumbprint = keyPair.Certificate.Thumbprint;
                KeyPairModel model;
                
                if (this.authorizedKeys.Contains(thumbprint)) {
                    model = new KeyPairModel(keyPair, KeyPairModel.Authorization.Authorized, provider);
                } else {
                    model = new KeyPairModel(keyPair, KeyPairModel.Authorization.Rejected, provider);
                }

                // replace existing keys with same thumbprint but different provider
                // ReSharper disable once AssignNullToNotNullAttribute
                this.knownKeys[thumbprint] = model;
            }
        }

        public IList<KeyPairModel> GetAvailableKeyPairs() {
            // clone list to prevent side effects
            return this.knownKeys.Values.Select(m => new KeyPairModel(m)).ToList();
        }
    }
}