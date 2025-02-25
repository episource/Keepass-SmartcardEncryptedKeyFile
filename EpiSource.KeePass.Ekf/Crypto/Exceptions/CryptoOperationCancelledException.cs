using System;
using System.Runtime.Serialization;

using EpiSource.KeePass.Ekf.Crypto.Windows;

namespace EpiSource.KeePass.Ekf.Crypto.Exceptions {
    [Serializable]
    public class CryptoOperationCancelledException : GenericCryptoException {

        public CryptoOperationCancelledException(string message, Exception innerException) : base(message, innerException, NativeCapi.CryptoResult.SCARD_W_CANCELLED_BY_USER) {
        }
        
        public CryptoOperationCancelledException(string message, Exception innerException, int errorCode) : base(message, innerException, errorCode) {
        }
        
        internal CryptoOperationCancelledException(string message, Exception innerException, NativeCapi.CryptoResult errorCode) : base(message, innerException, errorCode) {
        }
        
        protected CryptoOperationCancelledException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}