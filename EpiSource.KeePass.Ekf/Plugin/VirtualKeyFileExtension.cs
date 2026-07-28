using System;
using System.Linq;

using EpiSource.KeePass.Ekf.Util;

using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace EpiSource.KeePass.Ekf.Plugin {
    public static class VirtualKeyFileExtensions {
        /// <summary>
        /// Wraps a given plaintext key in a (virtual) <see cref="KcpKeyFile"/>:
        /// as if the plaintext key data was read from a key file by KeePass itself.
        /// This ensures EKF is 100% compatible with KeePass built-in key file support
        /// and the exported plain key can be read without this plugin.
        /// </summary>
        /// <param name="plaintextKey">The plaintext key to be wrapped.</param>
        /// <returns>A (virtual) key file of type <see cref="KcpKeyFile"/></returns>
        public static KcpKeyFile ToVirtualKeyFile(this PortableProtectedBinary plainKey) {
            var plainKeyData = plainKey.ReadUnprotected();
            var keyAsDataUri = StrUtil.DataToDataUri(plainKeyData, null);
            Array.Clear(plainKeyData, 0, plainKeyData.Length);
            var keyAsConnInfo = IOConnectionInfo.FromPath(keyAsDataUri);
            return new KcpKeyFile(keyAsConnInfo);
        }
        
        public static IUserKey GetEkfKey(this PwDatabase db) {
            if (db == null || db.MasterKey == null) {
                return null;
            }

            return db.MasterKey.GetEkfKey();
        }

        public static IUserKey GetEkfKey(this CompositeKey compositeKey) {
            if (compositeKey == null) {
                return null;
            }
            
            return compositeKey.UserKeys.SingleOrDefault(k =>
                k is KcpKeyFile ||
                k is KcpCustomKey && ((KcpCustomKey) k).Name == SmartcardEncryptedKeyProvider.ProviderName);
        }
    }
}