using System;

namespace EpiSource.KeePass.Ekf.UI.Windows {
    public class InvalidWindowHandleException : Exception {
        public InvalidWindowHandleException() : this(null) { }
        public InvalidWindowHandleException(Exception innerException) 
            : base("Invalid window handle", innerException) { }
        
    }
}