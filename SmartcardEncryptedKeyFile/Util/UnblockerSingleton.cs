using System;

using episource.unblocker;

namespace Episource.KeePass.EKF.Util {
    public static class UnblockerSingleton {
        private static Lazy<Unblocker> defaultInstance = new Lazy<Unblocker>(
            () => new Unblocker(standbyDelay: TimeSpan.FromSeconds(5)));
        public  static Unblocker DefaultInstance {
            get { return defaultInstance.Value; }
        }
    }
}