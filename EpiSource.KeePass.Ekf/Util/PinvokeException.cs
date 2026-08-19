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
        
        public PinvokeException(int lastErr, Exception innerException=null) 
                : this(string.Format("{0} (0x{1:X})", new Win32Exception(lastErr).Message, lastErr), lastErr, innerException: innerException) { }

        public PinvokeException(int lastErr, PinvokeUtil.PinvokeDescription pinvokeMethodDescription, Exception innerException = null)
            : this(string.Format("{0} (0x{1:X}) @ {2}", new Win32Exception(lastErr).Message, lastErr, pinvokeMethodDescription.Description), lastErr, pinvokeMethodDescription, innerException) { }

        protected PinvokeException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
        
    }
}