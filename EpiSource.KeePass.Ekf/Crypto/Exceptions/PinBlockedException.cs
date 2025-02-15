using System;
using System.Runtime.Serialization;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;

namespace EpiSource.KeePass.Ekf.Crypto.Windows.Exceptions {
    [Serializable]
    public class PinBlockedException : GenericCryptoException {

        public PinBlockedException(string message, Exception innerException) : base(message, innerException, NativeCapi.CryptoResult.SCARD_W_CHV_BLOCKED) {
        }
        
        protected PinBlockedException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}