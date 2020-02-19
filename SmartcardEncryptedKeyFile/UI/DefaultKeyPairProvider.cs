using System.Collections.Generic;
using System.Linq;

using Episource.KeePass.Ekf.KeyProvider;
using Episource.KeePass.EKF.Crypto;

using KeePassLib.Serialization;

namespace Episource.KeePass.EKF.UI {
    public class DefaultKeyPairProvider : IKeyPairProvider {
        private readonly IDictionary<string, IKeyPair> authorizedKeys;
        private readonly IDictionary<string, KeyPairModel> knownKeys = new Dictionary<string, KeyPairModel>();
        
        public DefaultKeyPairProvider(IOConnectionInfo dbPath) {
            var ekfPath = dbPath.ResolveEncryptedKeyFile();

            if (IOConnection.FileExists(ekfPath)) {
                using (var stream = IOConnection.OpenRead(ekfPath)) {
                    this.authorizedKeys = EncryptedKeyFile
                                          .Read(stream).Authorization
                                          .Where(kp => kp.Certificate.Thumbprint != null)
                                          .ToDictionary(kp => kp.Certificate.Thumbprint, kp => kp);
                }
            } else {
                this.authorizedKeys = new Dictionary<string, IKeyPair>();
            }

            this.Refresh();
        }

        public DefaultKeyPairProvider(EncryptedKeyFile ekf) {
            this.authorizedKeys = ekf.Authorization
                                     .Where(kp => kp.Certificate.Thumbprint != null)
                                     .ToDictionary(kp => kp.Certificate.Thumbprint, kp => kp);
            this.Refresh();
        }
        
        public IList<KeyPairModel> GetAvailableKeyPairs() {
            // clone list to prevent side effects
            return this.knownKeys.Values.Select(m => new KeyPairModel(m)).ToList();
        }

        public IList<KeyPairModel> GetAuthorizedKeyPairs() {
            // clone list to prevent side effects
            return this.knownKeys.Values
                       .Where(m => m.CurrentAuthorization == KeyPairModel.Authorization.Authorized)
                       .Select(m => new KeyPairModel(m)).ToList();
        }

        public bool Refresh() {
            var prevKnownKeys = this.knownKeys.ToDictionary(
                x => x.Key, x => x.Value);
            this.knownKeys.Clear();
            
            // add piv cards last: replace existing keys from other sources (piv is primary provider)
            this.AddKeys(this.authorizedKeys.Values, KeyPairModel.KeyProvider.EkfAuthorizationList);
            this.AddKeys(RSASmartcardKeyPairs.GetAllPivKeyPairs(), KeyPairModel.KeyProvider.Piv);

            var changed = false;
            foreach (var k in this.knownKeys) {
                KeyPairModel prevKeyModel;
                if (!prevKnownKeys.TryGetValue(k.Key, out prevKeyModel)) {
                    changed = true;
                    continue;
                }

                k.Value.NextAuthorization = prevKeyModel.NextAuthorization;
                changed |= IsSignificantlyDifferent(k.Value, prevKeyModel);
            }

            return changed;
        }

        private void AddKeys(IEnumerable<IKeyPair> keyPairs, KeyPairModel.KeyProvider provider) {
            foreach (var keyPair in keyPairs) {
                var thumbprint = keyPair.Certificate.Thumbprint;
                KeyPairModel model;
                
                if (thumbprint != null && this.authorizedKeys.ContainsKey(thumbprint)) {
                    model = new KeyPairModel(keyPair, KeyPairModel.Authorization.Authorized, provider);
                } else {
                    model = new KeyPairModel(keyPair, KeyPairModel.Authorization.Rejected, provider);
                }

                // replace existing keys with same thumbprint but different provider
                // ReSharper disable once AssignNullToNotNullAttribute
                this.knownKeys[thumbprint] = model;
            }
        }

        private static bool IsSignificantlyDifferent(KeyPairModel l, KeyPairModel r) {
            return l.Provider                     != r.Provider
                   || l.CurrentAuthorization      != r.CurrentAuthorization
                   || l.KeyPair.IsAccessible      != r.KeyPair.IsAccessible
                   || l.KeyPair.CanDecrypt        != r.KeyPair.CanDecrypt
                   || l.KeyPair.IsReadyForDecrypt != r.KeyPair.IsReadyForDecrypt
                   || l.KeyPair.CanEncrypt        != r.KeyPair.CanDecrypt
                   || l.KeyPair.IsReadyForEncrypt != r.KeyPair.IsReadyForEncrypt;
        }

    }
}