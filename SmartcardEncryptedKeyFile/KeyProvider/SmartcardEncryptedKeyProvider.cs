using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

using episource.unblocker;
using episource.unblocker.hosting;

using Episource.KeePass.EKF.Crypto;
using Episource.KeePass.EKF.Crypto.Windows;
using Episource.KeePass.EKF.UI;

using KeePass.Plugins;

using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;

using Microsoft.Win32.SafeHandles;

namespace Episource.KeePass.Ekf.KeyProvider {
    
    public class SmartcardEncryptedKeyProvider : KeePassLib.Keys.KeyProvider {
        
        public const string ProviderName = "Smartcard Encrypted Key File Provider";

        private readonly IPluginHost pluginHost;

        public SmartcardEncryptedKeyProvider(IPluginHost pluginHost) {
            if (pluginHost == null) {
                throw new ArgumentNullException("pluginHost");
            }

            this.pluginHost = pluginHost;
        }

        public override byte[] GetKey(KeyProviderQueryContext ctx) {
            var plainKey = ctx.CreatingNewKey ? this.CreateNewKey(ctx) : DecryptEncryptedKeyFile(ctx);
            if (plainKey == null) {
                return null;
            }

            // treat plaintext key as if it was read from a key file:
            // ensure ekf is 100% compatible with built-in key file support
            var keyAsDataUri = StrUtil.DataToDataUri(plainKey, null);
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
                    k is KcpKeyFile ||
                    k is KcpCustomKey && ((KcpCustomKey) k).Name == ProviderName);
            }

            var encryptionRequest = EditEncryptedKeyFileDialog.AskForNewEncryptedKeyFile(ctx.DatabaseIOInfo, activeKey);
            if (encryptionRequest == null) {
                return null;
            }

            encryptionRequest.WriteEncryptedKeyFile();
            return encryptionRequest.PlaintextKey;
        }

        private static byte[] DecryptEncryptedKeyFile(KeyProviderQueryContext ctx) {
            var ekfPath = ctx.DatabaseIOInfo.CloneDeep();
            ekfPath.Path += ".ekf";

            EncryptedKeyFile ekfFile;
            using (var stream = IOConnection.OpenRead(ekfPath)) {
                ekfFile = EncryptedKeyFile.Read(stream);
            }

            try {
                return SmartcardRequiredDialog
                       .DoCryptoWithMessagePump(ct => ekfFile.Decrypt()).PlaintextKey;
            } catch (TaskCanceledException) {
                return null;
            } catch (AggregateException e) {
                if (e.InnerExceptions.Count == 1 && e.InnerException is CryptographicException) {
                    // operation was canceled using windows dialog or failed otherwise
                    return null;
                }

                throw;
            }
        }
    }
}