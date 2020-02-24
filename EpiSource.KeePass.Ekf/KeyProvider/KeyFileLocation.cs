using KeePassLib;
using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.KeyProvider {
    public static class KeyFileLocation {
        public const string EkfExtension = ".ekf";
        
        public static IOConnectionInfo ResolveEncryptedKeyFile(this IOConnectionInfo dbPath) {
            if (dbPath == null) {
                return null;
            }
            
            if (dbPath.ToString().EndsWith(EkfExtension)) {
                return dbPath;
            }

            IOConnectionInfo ekfPath = dbPath.CloneDeep();
            ekfPath.Path += EkfExtension;

            return ekfPath;
        }

        public static IOConnectionInfo ResolveEncryptedKeyFile(this PwDatabase dbPath) {
            return ResolveEncryptedKeyFile(dbPath.IOConnectionInfo);
        }

        public static bool HasEncryptedKeyFile(this IOConnectionInfo dbPath) {
            return dbPath != null && IOConnection.FileExists(dbPath.ResolveEncryptedKeyFile());
        }

        public static bool HasEncryptedKeyFile(this PwDatabase db) {
            return db != null && HasEncryptedKeyFile(db.IOConnectionInfo);
        }
    }
}