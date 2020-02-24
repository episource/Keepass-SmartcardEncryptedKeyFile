using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.UI;

using EpiSource.Unblocker.Hosting;

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

            this.pluginHost.MainWindow.FileOpened += (sender, args) => editMenu.Enabled = this.CanEditEkf();
            this.pluginHost.MainWindow.FileClosed += (sender, args) => editMenu.Enabled = this.CanEditEkf();
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
            if (this.CanEditEkf()) {
                var encryptionRequest = EditEncryptedKeyFileDialog.AskForSettings(
                    this.pluginHost.Database.IOConnectionInfo, this.GetActiveEkfKey());
                if (encryptionRequest != null) {
                    encryptionRequest.WriteEncryptedKeyFile();
                }
            }
        }

        
        private bool CanEditEkf() {
            return this.pluginHost.Database.HasEncryptedKeyFile() && this.GetActiveEkfKey() != null;
        }
        
        private IUserKey GetActiveEkfKey() {
            var db = this.pluginHost.Database;
            if (db == null) {
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

        private byte[] DecryptEncryptedKeyFile(KeyProviderQueryContext ctx, bool retryOnCrash = true) {
            var ekfPath = ctx.DatabaseIOInfo.ResolveEncryptedKeyFile();

            EncryptedKeyFile ekfFile;
            using (var stream = IOConnection.OpenRead(ekfPath)) {
                ekfFile = EncryptedKeyFile.Read(stream);
            }

            var recipient = SmartcardRequiredDialog.ChooseKeyPairForDecryption(ekfFile, this.pluginHost.MainWindow);

            try {
                return SmartcardOperationDialog
                       .DoCryptoWithMessagePump(ct => ekfFile.Decrypt(recipient)).PlaintextKey;
            } catch (TaskCanceledException) {
                return null;
            } catch (AggregateException e) {
                if (e.InnerExceptions.Count == 1) {
                    if (e.InnerException is CryptographicException) {
                        // operation was canceled using windows dialog or failed otherwise
                        return null;
                    } 
                    if (e.InnerException is TaskCrashedException && retryOnCrash) {
                        // there's a known bug in win 10 credentials ui, that causes a crash when opening the dialog
                        // -> https://github.com/mRemoteNG/mRemoteNG/issues/853
                        // -> https://developercommunity.visualstudio.com/content/problem/352484/buffer-overflow-within-windowsuixamlhostdll-when-p.html
                        // retry once before failing!
                        return this.DecryptEncryptedKeyFile(ctx, false);
                    }
                } 

                throw;
            }
        }
    }
}