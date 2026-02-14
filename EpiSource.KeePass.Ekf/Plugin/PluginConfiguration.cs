using System;
using System.Runtime.CompilerServices;

using EpiSource.KeePass.Ekf.Util;
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
        private const string configKeyUseNativePinDialog = "EpiSource.KeePass.Ekf.UseNativePinDialog";

        public PluginConfiguration(AceCustomConfig keypassCustomConfig) {
            this.StrictRfc5753 = keypassCustomConfig.GetBool(configKeyStrictRfc5753, false);
            this.UseNativePinDialog = keypassCustomConfig.GetBool(configKeyUseNativePinDialog, false);
            
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

        public PortableProtectedBinary PinStoreKey {
            get;
            private set;
        }

        public string PinStoreKeyId {
            get;
            private set;
        }

        public bool StrictRfc5753 {
            get;
            private set;
        }
        
        public bool UseNativePinDialog {
            get;
            private set;
        }
    }
}