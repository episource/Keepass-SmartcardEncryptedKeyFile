using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    [Serializable]
    public class PinBlockedException : CryptographicException {
        
        public PinBlockedException(string message, Exception innerException) : base(message, innerException) {}
        
        protected PinBlockedException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}