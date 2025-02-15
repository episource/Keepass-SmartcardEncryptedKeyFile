using System;
using System.Collections.Generic;

using EpiSource.KeePass.Ekf.Util.Exceptions;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
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