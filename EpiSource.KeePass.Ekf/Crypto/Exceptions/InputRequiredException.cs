using System;
using System.Runtime.Serialization;

using EpiSource.KeePass.Ekf.Crypto.Windows;

namespace EpiSource.KeePass.Ekf.Crypto.Exceptions {
    [Serializable]
    public class InputRequiredException : GenericCryptoException {

        public InputRequiredException(string message, Exception innerException) : base(message, innerException, NativeCapi.CryptoResult.NTE_SILENT_CONTEXT) {
        }
        
        public InputRequiredException(string message, Exception innerException, int errorCode) : base(message, innerException, errorCode) {
        }
        
        internal InputRequiredException(string message, Exception innerException, NativeCapi.CryptoResult errorCode) : base(message, innerException, errorCode) {
        }
        
        protected InputRequiredException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}