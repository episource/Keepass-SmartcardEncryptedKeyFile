using System;
using System.IO;

using KeePassLib.Cryptography;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace EpiSource.KeePass.Ekf.Keys {
    public class ImportedKeyDataStore : IKeyDataStore {

        private readonly string fileName;

        public ImportedKeyDataStore(string fileName, byte[] importedKey) : this(fileName, new ProtectedBinary(true, importedKey)) {
        }
        
        public ImportedKeyDataStore(string fileName, ProtectedBinary importedKey) {
            this.fileName = fileName;
            this.KeyData = importedKey;
        }

        public static ImportedKeyDataStore FromKfxFile(string filePath) {
            using (var s = File.OpenRead(filePath)) {
                KfxFile kfxFile = null;
                
                try {
                    kfxFile = KfxFile.Load(s);
                } catch (Exception) {
                    // invalid key file. Plaintext key?
                    // => continue returning null
                }
                
                return kfxFile == null ? null : new ImportedKeyDataStore(Path.GetFileName(filePath), kfxFile.GetKey());
            } 
        }
        
        /**
         * Mimics the non-xml part of <see cref="KcpKeyFile.LoadKeyFile" />
         * See: https://github.com/ralish/KeePass/blob/v2.57.1/KeePassLib/Keys/KcpKeyFile.cs#L102-L119
         */
        public static ImportedKeyDataStore FromPlainKeyFile(string filePath) {
            var data = File.ReadAllBytes(filePath);
            var fileName = Path.GetFileName(filePath);

            if (data == null || data.Length == 0) {
                return null;
            }
            
            if (data.Length == 32) {
                return new ImportedKeyDataStore(fileName, data);
            }

            if (data.Length == 64) {
                if(!StrUtil.IsHexString(data, true)) return null;
                
                var strHex = StrUtil.Utf8.GetString(data);
                var hexKeyData = MemUtil.HexStringToByteArray(strHex);
                
                return new ImportedKeyDataStore(fileName, hexKeyData);
            }
            
            return new ImportedKeyDataStore(fileName, CryptoUtil.HashSha256(data));
        }

        public ProtectedBinary KeyData { get; private set; }

        public bool IsRandom {
            get { return false; }
        }

        public string FileName {
            get { return this.fileName; }
        }
    }
}