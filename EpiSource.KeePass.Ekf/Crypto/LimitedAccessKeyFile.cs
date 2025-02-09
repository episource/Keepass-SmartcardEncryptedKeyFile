using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace EpiSource.KeePass.Ekf.Util {
    [Serializable]
    public abstract class LimitedAccessKeyFile {
        private readonly IList<IKeyPair> authorization;
        
        protected LimitedAccessKeyFile(IEnumerable<IKeyPair> authorization) 
            : this(cloneAuthorization(authorization), true) { }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="authorization"></param>
        /// <param name="noCopyTakeOwnership">
        /// The caller guarantees, that no external references the to the authorization
        /// list and the contained key pair instances exist. This is e.g. the case when
        /// called from a deserialization constructor.
        /// </param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        protected LimitedAccessKeyFile(IList<IKeyPair> authorization, bool noCopyTakeOwnership) {
            if (authorization == null) {
                throw new ArgumentNullException("authorization");
            }

            // when invoked from a derived class' deserialization constructor, the items 
            // of the authorization list may not yet be fully deserialized (e.g. OnDeserialized
            // not yet executed). Creating a internal copy therefore is harmful.
            // Protective copying isn't needed either, as the authorization list just came
            // from the serialization engine, no foreign references exit.
            this.authorization = noCopyTakeOwnership ? authorization : cloneAuthorization(authorization);
        }

        private static IList<IKeyPair> cloneAuthorization(IEnumerable<IKeyPair> authorization) {
            var copyOfAuthorization = new List<IKeyPair>();
            foreach (var kp in authorization) {
                if (kp == null) {
                    throw new ArgumentException("`null` item in authorization list. Maybe invoked from deserialization constructor of derived class, without `noCopyTakeOwnership=true`?", "authorization");
                }
                if (!kp.GetType().IsSerializable) {
                    throw new ArgumentException("Not all authorized keys are serializable.", "authorization");
                }
                copyOfAuthorization.Add(kp);
            }
            return copyOfAuthorization;
        }
        
        public IList<IKeyPair> Authorization {
            get { return this.authorization; }
        }
    }
}