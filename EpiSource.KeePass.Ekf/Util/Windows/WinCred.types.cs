using System;

using EpiSource.KeePass.Ekf.Util;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public partial class WinCred {
        public enum CredentialPersistence {
            Session = 1,
            LocalMachine = 2,
            Enterprise = 3
        }
    }
}