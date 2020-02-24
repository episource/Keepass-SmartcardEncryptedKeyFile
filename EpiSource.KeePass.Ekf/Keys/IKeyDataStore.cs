using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Keys {
    public interface IKeyDataStore {
        ProtectedBinary KeyData { get; }
        bool IsRandom { get; }
    }
}