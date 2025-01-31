using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace EpiSource.KeePass.Ekf.Crypto {
    [Serializable]
    public class WrongPinException : CryptographicException {
        
        public WrongPinException(string message, Exception innerException) : base(message, innerException) {}
        
        protected WrongPinException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}