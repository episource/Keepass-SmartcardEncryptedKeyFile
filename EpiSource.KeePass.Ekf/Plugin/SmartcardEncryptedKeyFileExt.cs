using EpiSource.KeePass.Ekf.Plugin;

using KeePass.Plugins;


// KeePass requirement: Fully classified name of plugin class must be
// <AssemblyName>.<AssemblyName>Ext
// If AssemblyName is dots, this leads to duplicated namespace components.
// Due to KeePass plgx loader using AssemblyName where it should use RootNamespace when compiling embedded resources,
// the AssemblyName must be equal to the RootNamespace when embedded resources are present (or namespace of embedded
// resources must be changed to AssemblyName).
// => It has been decided to make AssemblyName equal to RootNamespace.

// ReSharper disable once CheckNamespace
namespace EpiSource.KeePass.Ekf.EpiSource.KeePass {
    // KeePass requirement:
    // ReSharper disable once UnusedMember.Global
    public class EkfExt : global::KeePass.Plugins.Plugin {
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