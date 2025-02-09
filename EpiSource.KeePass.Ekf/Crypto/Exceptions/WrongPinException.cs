using System;
using System.Runtime.Serialization;
using System.Security.Cryptography;

using EpiSource.KeePass.Ekf.Util.Windows;

namespace EpiSource.KeePass.Ekf.Util.Exceptions {
    [Serializable]
    public class WrongPinException : GenericCryptoException {

        public WrongPinException(string message, Exception innerException) : base(message, innerException, NativeCapi.CryptoResult.SCARD_W_WRONG_CHV) {
        }
        
        protected WrongPinException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}