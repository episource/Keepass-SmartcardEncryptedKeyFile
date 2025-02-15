using System;
using System.Collections.Generic;
using System.Linq;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.KeyProvider;

using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.UI {
    [Serializable]
    public class DefaultKeyPairProvider : IKeyPairProvider {
        private readonly IDictionary<string, IKeyPair> authorizedKeys;
        private readonly IDictionary<string, KeyPairModel> knownKeys = new Dictionary<string, KeyPairModel>();

        private struct KeyPairWithProvider {
            public IKeyPair KeyPair;
            public KeyPairModel.KeyProvider Provider;
        }


        private DefaultKeyPairProvider() {
            this.authorizedKeys = new Dictionary<string, IKeyPair>();
            this.Refresh();
        }
        
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        private DefaultKeyPairProvider(EncryptedKeyFile ekf) {
            this.authorizedKeys = ekf.Authorization
                                     .Where(kp => kp.Certificate.Thumbprint != null)
                                     .ToDictionary(kp => kp.Certificate.Thumbprint, kp => kp);
            this.Refresh();
        }

        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public static DefaultKeyPairProvider FromSystemKeyStore() {
            return new DefaultKeyPairProvider();
        }
        
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public static DefaultKeyPairProvider FromDbPath(IOConnectionInfo dbPath) {
            var ekfPath = dbPath.ResolveEncryptedKeyFile();

            if (!IOConnection.FileExists(ekfPath)) return new DefaultKeyPairProvider();
            using (var stream = IOConnection.OpenRead(ekfPath)) {
                return new DefaultKeyPairProvider(EncryptedKeyFile.Read(stream));
            }
        }

        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public static DefaultKeyPairProvider FromEncryptedKeyFile(EncryptedKeyFile ekf) {
            return new DefaultKeyPairProvider(ekf);
        }
        
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public static DefaultKeyPairProvider FromEncryptedKeyFileBinary(byte[] ekf) {
            return new DefaultKeyPairProvider(EncryptedKeyFile.Decode(ekf));
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
        
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public bool Refresh() {
            return this.RefreshImpl(
                RSASmartcardKeyPairs.GetAllPivKeyPairs() // NOTE: blocks if busy HW involved
                     .Select(k => new KeyPairWithProvider {KeyPair = k, Provider = KeyPairModel.KeyProvider.Piv}));
        }

        public bool Refresh(IKeyPairProvider other) {
            return this.RefreshImpl(
                other.GetAvailableKeyPairs()
                     .Select(m => new KeyPairWithProvider {KeyPair = m.KeyPair, Provider = m.Provider}));
        }

        private bool RefreshImpl(IEnumerable<KeyPairWithProvider> keys) {
            var prevKnownKeys = this.knownKeys.ToDictionary(
                x => x.Key, x => x.Value);
            this.knownKeys.Clear();
            
            foreach (var keyPair in this.authorizedKeys.Values) {
                this.AddKey(keyPair, KeyPairModel.KeyProvider.EkfAuthorizationList);
            }
            
            // add discovered key pairs last: replace existing entries based on authorization list
            foreach (var k in keys) {
                this.AddKey(k.KeyPair, k.Provider);
            }
            
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

        private void AddKey(IKeyPair keyPair, KeyPairModel.KeyProvider provider) {
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