using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.UI;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.Unblocker.Hosting;

using KeePass.Forms;
using KeePass.Plugins;

using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace EpiSource.KeePass.Ekf.KeyProvider {
    
    public class SmartcardEncryptedKeyProvider : KeePassLib.Keys.KeyProvider {
        
        public const string ProviderName = "Smartcard Encrypted Key File Provider";

        private readonly IPluginHost pluginHost;

        public SmartcardEncryptedKeyProvider(IPluginHost pluginHost) {
            if (pluginHost == null) {
                throw new ArgumentNullException("pluginHost");
            }
            
            this.pluginHost = pluginHost;
            
            var editMenu = new ToolStripMenuItem(Strings.SmartcardEncryptedKeyProvider_ButtonEditKeyFile);
            editMenu.Enabled = false;
            editMenu.Click += (sender, args) => this.EditEkf();
            this.pluginHost.MainWindow.ToolsMenu.DropDownItems.Add(editMenu);

            Action updateEditEkfMenuItem = 
                () => editMenu.Enabled = EditEncryptedKeyFileDialog.CanAskForSettings(this.GetActiveEkfKey());
            this.pluginHost.MainWindow.FileOpened += (sender, args) => updateEditEkfMenuItem();
            this.pluginHost.MainWindow.FileClosed += (sender, args) => updateEditEkfMenuItem();
        }

        public override byte[] GetKey(KeyProviderQueryContext ctx) {
            byte[] plainKey = null;
            try {
                plainKey = ctx.CreatingNewKey ? this.CreateNewKey(ctx) : this.DecryptEncryptedKeyFile(ctx);
            }
            catch (FileNotFoundException) {
                MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextEkfNotFound, ProviderName),
                    ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            }
            
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

        private void EditEkf() {
            var activeKey = this.GetActiveEkfKey();
            
            // treat missing EKF as empty EKF
            // permit edit as long as key (file) data is available
            if (EditEncryptedKeyFileDialog.CanAskForSettings(activeKey)) {
                var encryptionRequest = EditEncryptedKeyFileDialog.AskForSettings(
                    this.pluginHost.Database.IOConnectionInfo, this.GetActiveEkfKey());
                if (encryptionRequest != null) {
                    encryptionRequest.WriteEncryptedKeyFile();
                }
            }
        }

        private IUserKey GetActiveEkfKey() {
            var db = this.pluginHost.Database;
            if (db == null || db.MasterKey == null) {
                return null;
            }
            
            return db.MasterKey.UserKeys.SingleOrDefault(k =>
                k is KcpKeyFile ||
                k is KcpCustomKey && ((KcpCustomKey) k).Name == ProviderName);
        }

        private byte[] CreateNewKey(KeyProviderQueryContext ctx) {
            var activeDb = this.pluginHost.Database;
            IUserKey activeKey = null;
            if (string.Equals(ctx.DatabaseIOInfo.Path, activeDb.IOConnectionInfo.Path,
                StringComparison.InvariantCultureIgnoreCase)) {
                activeKey = this.GetActiveEkfKey();
            }

            var encryptionRequest = EditEncryptedKeyFileDialog.AskForNewEncryptedKeyFile(ctx.DatabaseIOInfo, activeKey);
            if (encryptionRequest == null) {
                return null;
            }

            encryptionRequest.WriteEncryptedKeyFile();
            return encryptionRequest.PlaintextKey;
        }

        private byte[] DecryptEncryptedKeyFile(KeyProviderQueryContext ctx, bool retryOnCrash = true, bool enableCancellation = true) {
            var ekfPath = ctx.DatabaseIOInfo.ResolveEncryptedKeyFile();

            EncryptedKeyFile ekfFile;
            using (var stream = IOConnection.OpenRead(ekfPath)) {
                // TODO: blocks if busy HW is involved - unblock!
                ekfFile = EncryptedKeyFile.Read(stream);
            }

            var recipient = SmartcardRequiredDialog.ChooseKeyPairForDecryption(ekfFile, this.pluginHost.MainWindow);
            if (recipient == null) {
                return null;
            }

            try {
                if (enableCancellation) {
                    return SmartcardOperationDialog
                           .DoCryptoWithMessagePump(ct => ekfFile.Decrypt(recipient)).PlaintextKey;
                } else {
                    return Task.Run(() => ekfFile.Decrypt(recipient)).AwaitWithMessagePump().PlaintextKey;
                }
            } catch (CryptographicException) {
                // operation was canceled using windows dialog or failed otherwise
                return null;
            } catch (DeniedByVirusScannerFalsePositive e) {
                var result = MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextUnblockerDeniedByVirusScanner, ProviderName, e.FilePath),
                    ProviderName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                return result == DialogResult.Yes ? this.DecryptEncryptedKeyFile(ctx, enableCancellation: false) : null;
            } catch (TaskCanceledException) {
                return null;
            } catch (TaskCrashedException) {
                if (retryOnCrash) {
                    // there's a known bug in win 10 credentials ui, that causes a crash when opening the dialog
                    // -> https://github.com/mRemoteNG/mRemoteNG/issues/853
                    // -> https://developercommunity.visualstudio.com/content/problem/352484/buffer-overflow-within-windowsuixamlhostdll-when-p.html
                    // retry once before failing!
                    return this.DecryptEncryptedKeyFile(ctx, false, enableCancellation);
                }
                throw;
            }
        }
    }
}