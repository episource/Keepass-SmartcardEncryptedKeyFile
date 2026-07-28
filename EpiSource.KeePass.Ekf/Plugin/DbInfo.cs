using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.Plugin {
    public interface DbInfo {
        IOConnectionInfo DbPath { get; }
        
    }
}