using System;
using System.Runtime.Serialization;

using EpiSource.KeePass.Ekf.Crypto.Windows;

namespace EpiSource.KeePass.Ekf.Crypto.Exceptions {
    public class MessageAuthenticationCodeMismatchException : GenericCryptoException {
        public MessageAuthenticationCodeMismatchException(string message, Exception innerException) : base(message, innerException) {
        }
        
        public MessageAuthenticationCodeMismatchException(string message, Exception innerException, int errorCode) : base(message, innerException) {
            this.HResult = errorCode;
        }
        
        internal MessageAuthenticationCodeMismatchException(string message, Exception innerException, NativeCapi.CryptoResult errorCode) : base(message, innerException) {
            this.HResult = unchecked((int)errorCode);
        } 
        
        protected MessageAuthenticationCodeMismatchException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}