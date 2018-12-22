using System;
using System.Collections.Generic;

namespace Episource.KeePass.EKF.Crypto {
    public abstract class LimitedAccessKeyFile {
        private readonly IList<IKeyPair> authorization;
        
        protected LimitedAccessKeyFile(IEnumerable<IKeyPair> authorization) {
            if (authorization == null) {
                throw new ArgumentNullException("authorization");
            }
            this.authorization = new List<IKeyPair>(authorization).AsReadOnly();
        }
        
        public IList<IKeyPair> Authorization {
            get { return this.authorization; }
        }
    }
}