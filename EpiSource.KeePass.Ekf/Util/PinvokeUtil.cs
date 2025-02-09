using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util {
    public static class PinvokeUtil {
        public sealed class PinvokeResult<T> {

            private T result;
            private int win32ErrorCode;
            public PinvokeResult(T result, int win32ErrorCode) {
                this.result = result;
                this.win32ErrorCode = win32ErrorCode;
            }

            public T Result { get { return this.result; } }
            public int Win32ErrorCode { get { return this.win32ErrorCode; } }
            
        }
        
        [DebuggerStepThrough]
        public static bool DoPinvokeWithException(this Func<bool> pinvokeFunc, Func<PinvokeResult<bool>, Exception> exceptionFactory = null) {
            return DoPinvokeDetailedWithException(pinvokeFunc, x => x.Result, exceptionFactory).Result;
        }
        
        [DebuggerStepThrough]
        public static T DoPinvokeWithException<T>(this Func<T> pinvokeFunc, Func<PinvokeResult<T>, bool> isGoodPredicate, Func<PinvokeResult<T>, Exception> exceptionFactory = null) {
            return DoPinvokeDetailedWithException(pinvokeFunc, isGoodPredicate, exceptionFactory).Result;
        }
        
        [DebuggerStepThrough]
        public static PinvokeResult<T> DoPinvokeDetailedWithException<T>(this Func<T> pinvokeFunc, Func<PinvokeResult<T>, bool> isGoodPredicate, Func<PinvokeResult<T>, Exception> exceptionFactory = null) {
            var result = pinvokeFunc();
            var lastErr = Marshal.GetLastWin32Error();
            var combinedResult = new PinvokeResult<T>(result, lastErr);
            
            if (isGoodPredicate(combinedResult)) return combinedResult;
            
            if (lastErr != 0) {
                var ex = exceptionFactory != null ? exceptionFactory.Invoke(combinedResult) : null;
                throw ex ?? new Win32Exception(lastErr);
            }

            throw new Win32Exception("Failed to invoke win32 api for unknown reasons. Result was: " + result + ", Win32 Error code: + " + lastErr);
        }
        
    }
}