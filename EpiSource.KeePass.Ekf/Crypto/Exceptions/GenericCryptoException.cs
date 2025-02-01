using System;
using System.ComponentModel;
using System.Runtime.Serialization;
using System.Security.Cryptography;

using EpiSource.KeePass.Ekf.Crypto.Windows;
using EpiSource.KeePass.Ekf.Crypto.Windows.Exceptions;

namespace EpiSource.KeePass.Ekf.Crypto.Exceptions {
    [Serializable]
    public class GenericCryptoException : CryptographicException {

        public GenericCryptoException(string message, Exception innerException) : base(message, innerException) {
        }
        
        public GenericCryptoException(string message, Exception innerException, int errorCode) : base(message, innerException) {
            this.HResult = errorCode;
        }
        
        internal GenericCryptoException(string message, Exception innerException, NativeCapi.CryptoResult errorCode) : base(message, innerException) {
            this.HResult = unchecked((int)errorCode);
        } 
        
        protected GenericCryptoException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}