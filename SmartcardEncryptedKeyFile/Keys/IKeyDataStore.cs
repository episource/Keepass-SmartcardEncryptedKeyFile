using KeePassLib.Security;

namespace Episource.KeePass.EKF.Keys {
    public interface IKeyDataStore {
        ProtectedBinary KeyData { get; }
        bool IsRandom { get; }
    }
}