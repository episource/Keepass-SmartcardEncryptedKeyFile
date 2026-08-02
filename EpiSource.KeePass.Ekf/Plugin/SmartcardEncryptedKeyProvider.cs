using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.Crypto.Windows;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.UI;
using EpiSource.KeePass.Ekf.UI.Windows;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.KeePass.Ekf.Util.Windows;
using EpiSource.Unblocker.Hosting;

using KeePass.Plugins;
using KeePass.UI;

using KeePassLib;
using KeePassLib.Keys;

namespace EpiSource.KeePass.Ekf.Plugin {
    
    public class SmartcardEncryptedKeyProvider : KeyProvider {
        
        public const string ProviderName = "Smartcard Encrypted Key File Provider";
        
        private readonly IPluginHost pluginHost;
        private readonly PluginConfiguration configuration;
        private readonly ProtectedWinCred rememberedSmartcardPinStore;
        private readonly UIFactory uiFactory;

        private KeyEncryptionRequest pendingKeyToSave = null;

        public SmartcardEncryptedKeyProvider(IPluginHost pluginHost) {
            if (pluginHost == null) {
                throw new ArgumentNullException("pluginHost");
            }
            
            this.pluginHost = pluginHost;
            this.configuration = new PluginConfiguration(this.pluginHost.CustomConfig, this.pluginHost.CommandLineArgs);
            if (this.configuration.AllocConsole) {
                NativeForms.AllocConsole();
            }
            
            this.uiFactory = new UIFactory(this.configuration);

            this.rememberedSmartcardPinStore = new ProtectedWinCred(this.configuration.PinStoreKey);
            
            var editMenu = new ToolStripMenuItem(Strings.SmartcardEncryptedKeyProvider_ButtonEditKeyFile);
            editMenu.Enabled = false;
            editMenu.Click += (sender, args) => this.EditEkf();
            this.pluginHost.MainWindow.ToolsMenu.DropDownItems.Add(editMenu);

            Action updateEditEkfMenuItem = 
                () => editMenu.Enabled = this.uiFactory.EditEncryptedKeyFileDialog
                                             .CanAskForSettings(this.GetActiveEkfKey());
            this.pluginHost.MainWindow.MasterKeyChanged += (sender, args) => updateEditEkfMenuItem();
            this.pluginHost.MainWindow.DocumentManager.ActiveDocumentSelected += (sender, args) => updateEditEkfMenuItem();
            
            this.pluginHost.MainWindow.MasterKeyChanged += (sender, args) => this.WritePendingEkfUpdate(args.Database);
            this.pluginHost.MainWindow.FileCreated += (sender, args) => this.WritePendingEkfUpdate(args.Database);
        }

        public override byte[] GetKey(KeyProviderQueryContext ctx) {
            PortableProtectedBinary plainKey;
            try {
                plainKey = ctx.CreatingNewKey ? this.CreateNewKey(ctx) : this.DecryptEncryptedKeyFile(ctx);
            } catch (FileNotFoundException) {
                MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextEkfNotFound, ProviderName),
                    ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            } catch (DeniedByVirusScannerFalsePositive e) {
                MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextUnblockerDeniedByVirusScanner, ProviderName, e.FilePath),
                    ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            } catch (Exception ex) {
                // strip InnerException if debug mode is disabled and messages are identical
                // => prevent duplicate text in error message
                if (ex.InnerException != null 
                        && ex.InnerException.Message == ex.Message
                        && this.configuration.DebugMode != DebugMode.None) {
                    throw new ApplicationException(ex.Message);
                }
                throw;
            }

            if (plainKey == null) {
                return null;
            }

            // treat plaintext key as if it was read from a key file:
            // ensure ekf is 100% compatible with built-in key file support
            // the KeePass builtin KcpKeyFile class also performs the necessary hashing,
            // therefore DirectKey==true is a valid choice.
            return plainKey.ToVirtualKeyFile().KeyData.ReadData();
        }

        public override string Name {
            get { return ProviderName; }
        }

        public override bool SecureDesktopCompatible {
            get { return !this.configuration.UseNativePinDialog; }
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
            if (this.uiFactory.EditEncryptedKeyFileDialog.CanAskForSettings(activeKey)) {
                try {
                    var encryptionRequest = this.uiFactory.EditEncryptedKeyFileDialog.AskForSettings(
                        this.pluginHost.Database, activeKey);
                    if (encryptionRequest != null) {
                        var ekfStore = new EkfStore(this.pluginHost.Database, this.configuration);
                        ekfStore.Write(encryptionRequest);
                    }
                } catch (DeniedByVirusScannerFalsePositive e) {
                    var result = MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextUnblockerDeniedByVirusScanner, ProviderName, e.FilePath),
                        ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        private IUserKey GetActiveEkfKey(bool includePlainKeyFile=true) {
            return this.pluginHost.Database.GetEkfKey(includePlainKeyFile);
        }

        private PortableProtectedBinary CreateNewKey(KeyProviderQueryContext ctx) {
            var activeDb = this.pluginHost.Database;
            
            PwDatabase db;
            if (string.Equals(ctx.DatabaseIOInfo.Path, activeDb.IOConnectionInfo.Path, StringComparison.InvariantCultureIgnoreCase)) {
                db = activeDb;
            } else {
                try {
                    db = PwDatabase.LoadHeader(ctx.DatabaseIOInfo);
                } catch (IOException) {
                    db = null;
                }
            }

            var encryptionRequest = this.uiFactory.EditEncryptedKeyFileDialog
                    .AskForNewEncryptedKeyFile(ctx.DatabaseIOInfo, db);
            this.pendingKeyToSave = encryptionRequest;
            return encryptionRequest == null ? null : encryptionRequest.PlaintextKey;
        }

        private PortableProtectedBinary DecryptEncryptedKeyFile(KeyProviderQueryContext ctx, bool retryOnCrash = true) {
            var ekfStore = new EkfStore(ctx.DatabaseIOInfo, this.configuration);
            
            // EncryptedKeyFile.Read/Decode blocks if busy HW is involved
            var ekfFile = ekfStore.Read(this.uiFactory);
            if (ekfFile == null) {
                throw new FileNotFoundException("no embedded nor external EKF data");
            }

            var recipient = this.uiFactory.SmartcardRequiredDialog
                .ChooseKeyPairForDecryption(ekfFile, GlobalWindowManager.TopWindow);
            try {
                return this.DecryptEncryptedKeyFile(ekfFile, recipient);
            } catch (TaskCrashedException) {
                if (retryOnCrash) {
                    // there's a known bug in win 10 credentials ui, that causes a crash when opening the dialog
                    // -> https://github.com/mRemoteNG/mRemoteNG/issues/853
                    // -> https://developercommunity.visualstudio.com/content/problem/352484/buffer-overflow-within-windowsuixamlhostdll-when-p.html
                    // retry once before failing!
                    return this.DecryptEncryptedKeyFile(ctx, false);
                }
                throw;
            } catch (DeniedByVirusScannerFalsePositive e) {
                var result = MessageBox.Show(string.Format(Strings.Culture, Strings.SmartcardEncryptedKeyProvider_DialogTextUnblockerDeniedByVirusScanner, ProviderName, e.FilePath),
                    ProviderName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            }
        }

        private PortableProtectedBinary DecryptEncryptedKeyFile(EncryptedKeyFile ekfFile, IKeyPair recipient) {
            if (recipient == null) {
                return null;
            }

            var storedPinTargetName = "KeePass.EKF@" + this.configuration.PinStoreKeyId + ".Cert:" + recipient.Certificate.Thumbprint + ":" + recipient.Certificate.Subject;
            storedPinTargetName = storedPinTargetName.Length > WinCred.MaxTargetNameLength ? storedPinTargetName.Substring(0, WinCred.MaxTargetNameLength) : storedPinTargetName;
            
            // start with remembered pin or null (if not found)
            // null: an attempt is made to access the smart card without pin. This works if the card is already unlocked.
            var pin = this.configuration.UseNativePinDialog ? null : this.rememberedSmartcardPinStore.ReadProtectedPassword(storedPinTargetName);
            PinPromptDialogFactory.PinPromptDialogResult pinPromptResult = null;
            while (pinPromptResult == null || !pinPromptResult.IsCanceled) { // retry on wrong pin
                if (pinPromptResult != null) {
                    pin = pinPromptResult.Pin;
                }

                try {
                    var decryptUiOwnerHandle = GlobalWindowManager.TopWindow.Handle;
                    var contextDescription = string.Format(Strings.Culture, Strings.NativeSmartcardUI_ContextTest, recipient.Certificate.SubjectName.Format(true));

                    var decryptedKeyFile = this.uiFactory.SmartcardOperationDialog
                            .DoCryptoWithMessagePump(ct => ekfFile.Decrypt(recipient, contextDescription,
                                    decryptUiOwnerHandle, !this.configuration.UseNativePinDialog, pin));

                    if (pinPromptResult != null && pinPromptResult.RememberPinRequested) {
                        this.rememberedSmartcardPinStore.WriteProtectedPassword(storedPinTargetName, pin);
                    }
                    
                    return decryptedKeyFile.PlaintextKey;
                } catch (TaskCanceledException) {
                    // cancelled by user
                    return null;
                } catch (CryptographicException ex) {
                    // operation was canceled using windows dialog or failed otherwise
                    if (NativeCapi.IsCancelledByUserException(ex)) {
                        return null;
                    }
                    if (NativeCapi.IsPinBlockedException(ex)) {
                        MessageBox.Show(Strings.PinBlockedDialog_DialogText, Strings.PinBlockedDialog_DialogTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return null;
                    }
                    
                    if (NativeCapi.IsInputRequiredException(ex)) {
                        pinPromptResult = this.uiFactory.PinPromptDialog.ShowDialog(
                            GlobalWindowManager.TopWindow, description: recipient.Certificate.Subject);
                    } else if (NativeCapi.IsWrongPinException(ex)) {
                        this.rememberedSmartcardPinStore.ClearProtectedPassword(storedPinTargetName);

                        if (this.configuration.UseNativePinDialog) {
                            return null;
                        }
                        
                        pinPromptResult = this.uiFactory.PinPromptDialog.ShowDialog(
                            GlobalWindowManager.TopWindow, description: recipient.Certificate.Subject, isRetry: true);
                    } else {
                        throw;
                    }

                }
            }
            
            return null;
        }

        private void WritePendingEkfUpdate(PwDatabase db) {
            var ekfStore = new EkfStore(db, this.configuration);
            
            if (this.pendingKeyToSave == null) {
                if (this.GetActiveEkfKey(includePlainKeyFile: false) == null) {
                    ekfStore.Clear();
                }
                
                return;
            }
            
            ekfStore.Write(this.pendingKeyToSave);
            this.pendingKeyToSave = null;
        }
    }
}