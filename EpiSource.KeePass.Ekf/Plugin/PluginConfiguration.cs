using System;
using System.Runtime.CompilerServices;

using EpiSource.KeePass.Ekf.Util;
using EpiSource.Unblocker.Hosting;
using EpiSource.Unblocker.Util;

using KeePass.App.Configuration;
using KeePass.Plugins;

using KeePassLib.Cryptography;
using KeePassLib.Utility;

namespace EpiSource.KeePass.Ekf.Plugin {
    public class PluginConfiguration {
        private const string configKeyPinStoreKey = "EpiSource.KeePass.Ekf.RememberedPinStoreKey";
        private const string configKeyPinStoreKeyId = "EpiSource.KeePass.Ekf.RememberedPinStoreKeyId";
        private const string configKeyStrictRfc5753 = "EpiSource.KeePass.Ekf.StrictRfc5753";
        private const string configKeyUnblockerBootstrapMode = "EpiSource.KeePass.Ekf.UnblockerBootstrapMode";
        private const string configKeyUseNativePinDialog = "EpiSource.KeePass.Ekf.UseNativePinDialog";

        public PluginConfiguration(AceCustomConfig keypassCustomConfig) {
            this.DebugMode = Environment.CommandLine.ToLowerInvariant().Contains("--debug");
            
            this.StrictRfc5753 = keypassCustomConfig.GetBool(configKeyStrictRfc5753, false);
            this.UseNativePinDialog = keypassCustomConfig.GetBool(configKeyUseNativePinDialog, false);

            var bootstrapMode = BootstrapMode.CustomBootstrapper;
            BootstrapMode.TryParse(keypassCustomConfig.GetString(configKeyUnblockerBootstrapMode), true, out bootstrapMode);
            this.UnblockerBootstrapMode = bootstrapMode;
            
            
            var keyId = keypassCustomConfig.GetString(configKeyPinStoreKeyId);
            if (keyId == null) {
                keyId = string.Format("{0:X8}", BobJenkinsOneAtATimeHash.CalculateHash(DateTime.Now.ToString("yyyyMMddHHmmssfff")));
                keypassCustomConfig.SetString(configKeyPinStoreKeyId, keyId);
            }
            this.PinStoreKeyId = keyId;
            
            var keyHexString = keypassCustomConfig.GetString(configKeyPinStoreKey);
            
            var keyBytes = keyHexString == null ? null : MemUtil.HexStringToByteArray(keyHexString);
            if (keyBytes == null) {
                keyBytes = CryptoRandom.Instance.GetRandomBytes(32);
                keypassCustomConfig.SetString(configKeyPinStoreKey, MemUtil.ByteArrayToHexString(keyBytes));
            }
            this.PinStoreKey = PortableProtectedBinary.Move(keyBytes);
        }

        /// <summary>
        /// Whether debug output should be enabled. Use command line argument `--debug` to enable.
        /// </summary>
        public bool DebugMode {
            get;
            private set;
        }

        /// <summary>
        /// Remembered PIN Store key. Loaded from KeePass configuration file. Random key created if configuration
        /// is missing.
        /// </summary>
        public PortableProtectedBinary PinStoreKey {
            get;
            private set;
        }

        /// <summary>
        /// Remembered PIN Store key ID. Loaded from KeyPass configuration file. New ID created if configuration
        /// is missing.
        /// </summary>
        public string PinStoreKeyId {
            get;
            private set;
        }

        /// <summary>
        /// Enable `strict RFC5753` mode for ECC encrypted enveloped CMS content. Default is `false`. Manually
        /// add a configuration node matching <see cref="configKeyStrictRfc5753"/> to KeePass configuration file to
        /// configure. Refer to README for details.
        /// </summary>
        public bool StrictRfc5753 {
            get;
            private set;
        }

        /// <summary>
        /// In company controlled environments with strict threat protection system the smart card worker process might
        /// fail to start. This option provides some tweaks to improve compatibility. Manually add a configuration
        /// node matching <see cref="configKeyUnblockerBootstrapMode"/> to KeePass configuration file to configure this.
        /// Refer to README for further information.
        /// </summary>
        public BootstrapMode UnblockerBootstrapMode {
            get;
            private set;
        }
        
        /// <summary>
        /// Use windows builtin Pin dialog instead of custom dialog. Default is `false`. Manually add a configuration
        /// node matching <see cref="configKeyUseNativePinDialog"/> to KeePass configuration file to configure.
        /// Refer to README for details.
        /// </summary>
        public bool UseNativePinDialog {
            get;
            private set;
        }
    }
}