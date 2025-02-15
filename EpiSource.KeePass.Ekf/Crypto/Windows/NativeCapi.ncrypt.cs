using System;
using System.Collections.Generic;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey
        private enum CryptPrivateKeySpec {
            UNDEFINED             = 0,
            AT_KEYEXCHANGE        = 1,
            AT_SIGNATURE          = 2,
            CERT_NCRYPT_KEY_SPEC  = unchecked((int)0xffffffff),
        }
        
        private static CryptoResult DoNcryptWithException(Func<CryptoResult> ncryptFunction, params CryptoResult[] validResults) {
            var internalResult = ncryptFunction();
            if (ncryptFunction() != CryptoResult.ERROR_SUCCESS && (validResults == null || !((IList<CryptoResult>)validResults).Contains(internalResult))) {
                throw CryptoExceptionFactory.forErrorCode(internalResult);
            }
            return internalResult;
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
        private static byte[] GetNcryptProperty(NCryptContextHandle keyHandle, string propertyName) {
            var valueSize = 0;
            DoNcryptWithException(() => NativeNCryptPinvoke.NCryptGetProperty(keyHandle, propertyName, null, 0, out valueSize, NCryptGetPropertyFlags.None));
                
            var value = new byte[valueSize];
            DoNcryptWithException(() => NativeNCryptPinvoke.NCryptGetProperty(keyHandle, propertyName, value, value.Length, out valueSize, NCryptGetPropertyFlags.None));

            Array.Resize(ref value, valueSize);
            return value;
        }
        
        private static void SetNcryptProperty(NCryptContextHandle keyHandle, string propertyName, byte[] value, NCryptSetPropertyFlags flags) {
            DoNcryptWithException(() => NativeNCryptPinvoke.NCryptSetProperty(keyHandle, propertyName, value, value.Length , flags));
        }
    }
}