using System;

using Episource.KeePass.EKF.Crypto;

namespace Episource.KeePass.EKF.UI {
    public class KeyPairModel {
        public enum KeyProvider {
            Piv,
            OpenPGP,
            HbciRdhCard,
            EkfAuthorizationList
        }

        public enum Authorization {
            Authorized,
            Rejected
        }
        
        private readonly IKeyPair keyPair;
        private readonly Authorization currentAuthorization;
        private readonly KeyProvider provider;

        public KeyPairModel(KeyPairModel model) : this(model.keyPair, model.currentAuthorization, model.provider) {}
        
        public KeyPairModel(IKeyPair keyPair, Authorization currentAuthorization, KeyProvider provider) {
            if (keyPair == null) {
                throw new ArgumentNullException(paramName: "keyPair");
            }
            if (provider == KeyProvider.EkfAuthorizationList && currentAuthorization != Authorization.Authorized) {
                throw new ArgumentException(message: "source == EkfAuthorizationList, but not authorized",
                    paramName: "currentAuthorization");
            }
            
            this.keyPair = keyPair;
            this.currentAuthorization = currentAuthorization;
            this.provider = provider;

            this.NextAuthorization = currentAuthorization;
        }

        public IKeyPair KeyPair {
            get { return this.keyPair; }
        }
        
        public Authorization CurrentAuthorization {
            get { return this.currentAuthorization; }
        }
        
        public KeyProvider Provider {
            get { return this.provider; }
        }
        
        public Authorization NextAuthorization { get;  set; }
    }
}