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
        private static byte[] GetNcryptProperty(NCryptContextHandle keyHandle, string propertyName, NCryptGetPropertyFlags flags) {
            var valueSize = 0;
            var result = DoNcryptWithException(() => NativeNCryptPinvoke.NCryptGetProperty(keyHandle, propertyName, null, 0, out valueSize, flags),
                CryptoResult.NTE_INVALID_PARAMETER, CryptoResult.NTE_NOT_SUPPORTED);

            if (result != CryptoResult.ERROR_SUCCESS) {
                return Array.Empty<byte>();
            }
                
            var value = new byte[valueSize];
            DoNcryptWithException(() => NativeNCryptPinvoke.NCryptGetProperty(keyHandle, propertyName, value, value.Length, out valueSize, flags));

            Array.Resize(ref value, valueSize);
            return value;
        }
        
        private static void SetNcryptProperty(NCryptContextHandle keyHandle, string propertyName, byte[] value, NCryptSetPropertyFlags flags) {
            DoNcryptWithException(() => NativeNCryptPinvoke.NCryptSetProperty(keyHandle, propertyName, value, value.Length , flags));
        }
    }
}