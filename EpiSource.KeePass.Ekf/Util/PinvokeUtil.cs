using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util {
    public static class PinvokeUtil {
        [DebuggerStepThrough]
        public static bool DoPinvokeWithException(Func<bool> pinvokeFunc) {
            return DoPinvokeWithException(pinvokeFunc, x => x);
        }
        
        [DebuggerStepThrough]
        public static T DoPinvokeWithException<T>(Func<T> pinvokeFunc, Func<T, bool> isGoodPredicate) {
            var result = pinvokeFunc();
            if (!isGoodPredicate(result)) {
                var lastErr = Marshal.GetLastWin32Error();
                if (lastErr != 0) {
                    throw new Win32Exception(lastErr);
                }

                throw new Win32Exception("Failed to invoke win32 api for unknown reasons.");
            }

            return result;
        }
    }
}