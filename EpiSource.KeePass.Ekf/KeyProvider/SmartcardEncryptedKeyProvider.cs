using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.Crypto.Windows;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.UI;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.KeePass.Ekf.Util.Windows;
using EpiSource.Unblocker.Hosting;
using EpiSource.Unblocker.Util;

using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;

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
            } catch (FileNotFoundException) {
                MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextEkfNotFound, ProviderName),
                    ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            } catch (DeniedByVirusScannerFalsePositive e) {
                var result = MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextUnblockerDeniedByVirusScanner, ProviderName, e.FilePath),
                    ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
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

        // This plugin only provides secure desktop support for Win10.
        // See also: SmartCardOperationDialog#SetDesktopAndExecute
        public override bool SecureDesktopCompatible {
            
            get { return WinVersion.IsWin10; }
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
                try {
                    var encryptionRequest = EditEncryptedKeyFileDialog.AskForSettings(
                        this.pluginHost.Database.IOConnectionInfo, this.GetActiveEkfKey());
                    if (encryptionRequest != null) {
                        encryptionRequest.WriteEncryptedKeyFile();
                    }
                } catch (DeniedByVirusScannerFalsePositive e) {
                    var result = MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextUnblockerDeniedByVirusScanner, ProviderName, e.FilePath),
                        ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
            // IOConnection not serializable - need to read file outside unlocker task
            var ekfPath = ctx.DatabaseIOInfo.ResolveEncryptedKeyFile();
            var encryptedKeyFileData = IOConnection.OpenRead(ekfPath).ReadAllBinaryAndClose();
            
            // EncryptedKeyFile.Read/Decode blocks if busy HW is involved
            var ekfFile = SmartcardOperationDialog
                .DoCryptoWithMessagePumpShort(ct => EncryptedKeyFile.Decode(encryptedKeyFileData));

            var recipient = SmartcardRequiredDialog.ChooseKeyPairForDecryption(ekfFile, GlobalWindowManager.TopWindow);
            if (recipient == null) {
                return null;
            }

            try {
                var decryptUiOwnerHandle = GlobalWindowManager.TopWindow.Handle;
                var contextDescription = string.Format(Strings.Culture, Strings.NativeSmartcardUI_ContextTest, recipient.Certificate.SubjectName.Format(true));
                
                if (enableCancellation) {
                    return SmartcardOperationDialog
                           .DoCryptoWithMessagePump(ct => ekfFile.Decrypt(recipient, contextDescription, decryptUiOwnerHandle, null)).PlaintextKey;
                }
                return Task.Run(() => ekfFile.Decrypt(recipient, contextDescription, decryptUiOwnerHandle, null)).AwaitWithMessagePump().PlaintextKey;
            } catch (OperationCanceledException e) {
                return null;
            } catch (CryptographicException ex) { 
                // operation was canceled using windows dialog or failed otherwise
                if (NativeCapi.IsCancelledByUserException(ex)) {
                    return null;
                }
                if (NativeCapi.IsWrongPinException(ex)) {
                    MessageBox.Show(Strings.WrongPinDialog_DialogText, Strings.WrongPinDialog_DialogTitle, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return null;
                }
                if (NativeCapi.IsPinBlockedException(ex)) {
                    MessageBox.Show(Strings.PinBlockedDialog_DialogText, Strings.PinBlockedDialog_DialogTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return null;
                }

                throw;
            } catch (DeniedByVirusScannerFalsePositive e) {
                var result = MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextUnblockerDeniedByVirusScanner, ProviderName, e.FilePath),
                    ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
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