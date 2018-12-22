using Episource.KeePass.Ekf.KeyProvider;

using KeePass.Plugins;

namespace SmartcardEncryptedKeyFile {
    public class SmartcardEncryptedKeyFileExt : Plugin {
        private IPluginHost pluginHost;

        public override bool Initialize(IPluginHost host) {
            if (this.pluginHost != null) {
                return false;
            }

            this.pluginHost = host;
            this.pluginHost.KeyProviderPool.Add(new SmartcardEncryptedKeyProvider(this.pluginHost));
            return true;
        }
    }
}