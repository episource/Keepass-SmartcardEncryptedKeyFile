using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util {
    public static class PinvokeUtil {
        [DebuggerStepThrough]
        public static bool DoPinvokeWithException(this Func<bool> pinvokeFunc, Func<int, Exception> exceptionFactory = null) {
            return DoPinvokeWithException(pinvokeFunc, x => x, exceptionFactory);
        }
        
        [DebuggerStepThrough]
        public static T DoPinvokeWithException<T>(this Func<T> pinvokeFunc, Func<T, bool> isGoodPredicate, Func<int, Exception> exceptionFactory = null) {
            var result = pinvokeFunc();
            if (isGoodPredicate(result)) return result;
            
            var lastErr = Marshal.GetLastWin32Error();
            if (lastErr != 0) {
                var ex = exceptionFactory != null ? exceptionFactory.Invoke(lastErr) : null;
                throw exceptionFactory != null ? ex : new Win32Exception(lastErr);
            }

            throw new Win32Exception("Failed to invoke win32 api for unknown reasons. Result was: " + result);

        }
    }
}