using System;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.Serialization;

namespace EpiSource.KeePass.Ekf.Util {
    [Serializable]
    public class PinvokeException : Win32Exception {

        public PinvokeException(string message, PinvokeUtil.PinvokeDescription pinvokeMethodDescription, Exception innerException = null) 
                : base(message, innerException) {
            this.SetPinvokeData(pinvokeMethodDescription);
        }

        public PinvokeException(string message, int lastErr, PinvokeUtil.PinvokeDescription pinvokeMethodDescription=default(PinvokeUtil.PinvokeDescription), Exception innerException = null) 
                : this(message, pinvokeMethodDescription, innerException) {
            this.HResult = lastErr;
        }
        
        public PinvokeException(int lastErr, PinvokeUtil.PinvokeDescription pinvokeMethodDescription=default(PinvokeUtil.PinvokeDescription), Exception innerException = null)
            : this(PinvokeUtil.DescribeLastWin32Error(lastErr, pinvokeMethodDescription), lastErr, pinvokeMethodDescription, innerException) { }

        protected PinvokeException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
        
    }
}