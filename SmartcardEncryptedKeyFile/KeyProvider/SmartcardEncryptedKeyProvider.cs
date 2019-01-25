using System;
using System.Diagnostics;
using System.Linq;

using Episource.KeePass.EKF.Crypto;
using Episource.KeePass.EKF.UI;

using KeePass.Plugins;

using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace Episource.KeePass.Ekf.KeyProvider {
    public class SmartcardEncryptedKeyProvider : KeePassLib.Keys.KeyProvider {
        public const string ProviderName = "Smartcard Encrypted Key File Provider";

        private readonly IPluginHost pluginHost;

        public SmartcardEncryptedKeyProvider(IPluginHost pluginHost) {
            if (pluginHost == null) {
                throw new ArgumentNullException(paramName: "pluginHost");
            }
            
            this.pluginHost = pluginHost;
        }
        
        public override byte[] GetKey(KeyProviderQueryContext ctx) {
            Debug.Assert(ctx.DatabasePath == this.pluginHost.Database.IOConnectionInfo.Path, 
                "Database and context path differet: " 
                + ctx.DatabasePath + ", " + this.pluginHost.Database.IOConnectionInfo.Path);
            
            var plainKey = ctx.CreatingNewKey ? this.CreateNewKey(ctx) : this.DecryptEncryptedKeyFile(ctx);
            if (plainKey == null) {
                return null;
            }
            
            // treat plaintext key as if it was read from a key file:
            // ensure ekf is 100% compatible with built-in key file support
            var keyAsDataUri = StrUtil.DataToDataUri(plainKey, strMimeType: null);
            var keyAsConnInfo = IOConnectionInfo.FromPath(keyAsDataUri);
            var virtualKeyFile = new KcpKeyFile(keyAsConnInfo);

            return virtualKeyFile.KeyData.ReadData();
        }
        
        public override string Name {
            get { return ProviderName; }
        }

        public override bool SecureDesktopCompatible {
            get { return true; }
        }

        public override bool DirectKey {
            get {
                // To ensure compatibility with the plain key file, this provider wraps KcpKeyFile
                // KcpKeyFile does the necessary hashing internally
                // => return true instead of recommended value false
                return true;
            }
        }

        private byte[] CreateNewKey(KeyProviderQueryContext ctx) {
            var activeDb = this.pluginHost.Database;
            IUserKey activeKey = null;
            if (string.Equals(ctx.DatabaseIOInfo.Path, activeDb.IOConnectionInfo.Path,
                StringComparison.InvariantCultureIgnoreCase)) {
                activeKey = activeDb.MasterKey.UserKeys.SingleOrDefault(k =>
                    k is KcpKeyFile || k is KcpCustomKey && ((KcpCustomKey) k).Name == ProviderName);
            }
            
            var encryptionRequest = EditEncryptedKeyFileDialog.AskForNewEncryptedKeyFile(ctx.DatabaseIOInfo, activeKey);
            if (encryptionRequest == null) {
                return null;
            }
            
            encryptionRequest.WriteEncryptedKeyFile();
            return encryptionRequest.PlaintextKey;
        }

        private byte[] DecryptEncryptedKeyFile(KeyProviderQueryContext ctx) {
            var ekfPath = ctx.DatabaseIOInfo.CloneDeep();
            ekfPath.Path += ".ekf";

            using (var stream = IOConnection.OpenRead(ekfPath)) {
                return EncryptedKeyFile.Read(stream).Decrypt().PlaintextKey;    
            }
        }
    }
}