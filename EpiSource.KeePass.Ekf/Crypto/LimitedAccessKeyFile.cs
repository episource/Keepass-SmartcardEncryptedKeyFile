using System;
using System.Collections.Generic;

namespace EpiSource.KeePass.Ekf.Crypto {
    [Serializable]
    public abstract class LimitedAccessKeyFile {
        private readonly IList<IKeyPair> authorization;
        
        protected LimitedAccessKeyFile(IEnumerable<IKeyPair> authorization) {
            if (authorization == null) {
                throw new ArgumentNullException("authorization");
            }

            var copyOfAuthorization = new List<IKeyPair>();
            foreach (var kp in authorization) {
                if (!kp.GetType().IsSerializable) {
                    throw new ArgumentException("Not all authorized keys are serializable.", "authorization");
                }
                copyOfAuthorization.Add(kp);
            }

            this.authorization = copyOfAuthorization.AsReadOnly();
        }
        
        public IList<IKeyPair> Authorization {
            get { return this.authorization; }
        }
    }
}