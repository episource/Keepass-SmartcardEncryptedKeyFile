using System.ComponentModel;

using EpiSource.KeePass.Ekf.Util.Windows;
using EpiSource.KeePass.Ekf.Util.Windows.Exceptions;

namespace EpiSource.KeePass.Ekf.Util.Exceptions {
    public static class CryptoExceptionFactory {

        public static GenericCryptoException forErrorCode(int errorCode) {
            return forErrorCode(unchecked((NativeCapi.CryptoResult) errorCode));
        }
        internal static GenericCryptoException forErrorCode(NativeCapi.CryptoResult errorCode) {
            var w32Exception = new Win32Exception(unchecked((int)errorCode));
            
            switch (errorCode) {
                case NativeCapi.CryptoResult.NTE_SILENT_CONTEXT:
                    return new InputRequiredException(w32Exception.Message, w32Exception, errorCode);
                case NativeCapi.CryptoResult.SCARD_W_WRONG_CHV:
                    return new WrongPinException(w32Exception.Message, w32Exception);
                case NativeCapi.CryptoResult.SCARD_W_CHV_BLOCKED:
                    return new PinBlockedException(w32Exception.Message, w32Exception);
                case NativeCapi.CryptoResult.SCARD_W_CANCELLED_BY_USER:
                    return new CryptoOperationCancelledException(w32Exception.Message, w32Exception, errorCode);
                default:
                    return new GenericCryptoException(w32Exception.Message, w32Exception, errorCode);
            }
        }

        internal static GenericCryptoException asException(this NativeCapi.CryptoResult errorCode) {
            return forErrorCode(errorCode);
        }
    }
}