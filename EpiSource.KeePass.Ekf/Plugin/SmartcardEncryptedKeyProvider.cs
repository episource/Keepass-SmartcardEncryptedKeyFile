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

using KeePass.Plugins;
using KeePass.UI;

using KeePassLib.Cryptography;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Utility;

namespace EpiSource.KeePass.Ekf.Plugin {
    
    public class SmartcardEncryptedKeyProvider : KeePassLib.Keys.KeyProvider {
        
        public const string ProviderName = "Smartcard Encrypted Key File Provider";
        private const string configKeyUseNativePinDialog = "EpiSource.KeePass.Ekf.UseNativePinDialog";
        private const string configKeyPinStoreKey = "EpiSource.KeePass.Ekf.RememberedPinStoreKey";
        private const string configKeyPinStoreKeyId = "EpiSource.KeePass.Ekf.RememberedPinStoreKeyId";

        private readonly IPluginHost pluginHost;
        private readonly string rememberedSmartcardPinStoreKeyId;
        private readonly ProtectedWinCred rememberedSmartcardPinStore;
        private readonly bool useNativePinDialog;

        public SmartcardEncryptedKeyProvider(IPluginHost pluginHost) {
            if (pluginHost == null) {
                throw new ArgumentNullException("pluginHost");
            }
            
            this.pluginHost = pluginHost;

            PortableProtectedBinary rememberedSmartcardPinStoreKey;
            this.GetOrCreatePinStoreKey(out rememberedSmartcardPinStoreKey, out this.rememberedSmartcardPinStoreKeyId);
            this.rememberedSmartcardPinStore = new ProtectedWinCred(rememberedSmartcardPinStoreKey);
            
            this.useNativePinDialog = this.pluginHost.CustomConfig.GetBool(configKeyUseNativePinDialog, false);
            
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
            }

            if (plainKey == null) {
                return null;
            }

            // treat plaintext key as if it was read from a key file:
            // ensure ekf is 100% compatible with built-in key file support
            var plainKeyData = plainKey.ReadUnprotected();
            var keyAsDataUri = StrUtil.DataToDataUri(plainKeyData, null);
            Array.Clear(plainKeyData, 0, plainKeyData.Length);
            var keyAsConnInfo = IOConnectionInfo.FromPath(keyAsDataUri);
            var virtualKeyFile = new KcpKeyFile(keyAsConnInfo);

            return virtualKeyFile.KeyData.ReadData();
        }

        public override string Name {
            get { return ProviderName; }
        }

        public override bool SecureDesktopCompatible {
            get { return !this.useNativePinDialog; }
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

        private PortableProtectedBinary CreateNewKey(KeyProviderQueryContext ctx) {
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

        private PortableProtectedBinary DecryptEncryptedKeyFile(KeyProviderQueryContext ctx, bool retryOnCrash = true) {
            // IOConnection not serializable - need to read file outside unlocker task
            var ekfPath = ctx.DatabaseIOInfo.ResolveEncryptedKeyFile();
            var encryptedKeyFileData = IOConnection.OpenRead(ekfPath).ReadAllBinaryAndClose();

            // EncryptedKeyFile.Read/Decode blocks if busy HW is involved
            var ekfFile = SmartcardOperationDialog
                .DoCryptoWithMessagePumpShort(ct => EncryptedKeyFile.Decode(encryptedKeyFileData));

            var recipient = SmartcardRequiredDialog.ChooseKeyPairForDecryption(ekfFile, GlobalWindowManager.TopWindow);
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

            var storedPinTargetName = "KeePass.EKF@" + this.rememberedSmartcardPinStoreKeyId + ".Cert:" + recipient.Certificate.Thumbprint + ":" + recipient.Certificate.Subject;
            storedPinTargetName = storedPinTargetName.Length > WinCred.MaxTargetNameLength ? storedPinTargetName.Substring(0, WinCred.MaxTargetNameLength) : storedPinTargetName;
            
            // start with remembered pin or null (if not found)
            // null: an attempt is made to access the smart card without pin. This works if the card is already unlocked.
            var pin = this.useNativePinDialog ? null : this.rememberedSmartcardPinStore.ReadProtectedPassword(storedPinTargetName);
            PinPromptDialog.PinPromptDialogResult pinPromptResult = null;
            while (pinPromptResult == null || !pinPromptResult.IsCanceled) { // retry on wrong pin
                if (pinPromptResult != null) {
                    pin = pinPromptResult.Pin;
                }

                try {
                    var decryptUiOwnerHandle = GlobalWindowManager.TopWindow.Handle;
                    var contextDescription = string.Format(Strings.Culture, Strings.NativeSmartcardUI_ContextTest, recipient.Certificate.SubjectName.Format(true));

                    var decryptedKeyFile = SmartcardOperationDialog.DoCryptoWithMessagePump(ct => ekfFile.Decrypt(recipient, contextDescription, decryptUiOwnerHandle, !this.useNativePinDialog, pin));

                    if (pinPromptResult != null && pinPromptResult.RememberPinRequested) {
                        this.rememberedSmartcardPinStore.WriteProtectedPassword(storedPinTargetName, pin);
                    }
                    
                    return decryptedKeyFile.PlaintextKey;
                } catch (TaskCanceledException e) {
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
                        pinPromptResult = PinPromptDialog.ShowDialog(GlobalWindowManager.TopWindow, description: recipient.Certificate.Subject);
                    } else if (NativeCapi.IsWrongPinException(ex)) {
                        this.rememberedSmartcardPinStore.ClearProtectedPassword(storedPinTargetName);

                        if (this.useNativePinDialog) {
                            return null;
                        }
                        
                        pinPromptResult = PinPromptDialog.ShowDialog(GlobalWindowManager.TopWindow, description: recipient.Certificate.Subject, isRetry: true);
                    } else {
                        throw;
                    }

                }
            }
            
            return null;
        }

        private void GetOrCreatePinStoreKey(out PortableProtectedBinary key, out string keyId) {
            var keyHexString = this.pluginHost.CustomConfig.GetString(configKeyPinStoreKey);
            
            var keyBytes = keyHexString == null ? null : MemUtil.HexStringToByteArray(keyHexString);
            if (keyBytes == null) {
                keyBytes = CryptoRandom.Instance.GetRandomBytes(32);
                this.pluginHost.CustomConfig.SetString(configKeyPinStoreKey, MemUtil.ByteArrayToHexString(keyBytes));
            }
            key = PortableProtectedBinary.Move(keyBytes);
            
            keyId = this.pluginHost.CustomConfig.GetString(configKeyPinStoreKeyId);
            if (keyId == null) {
                keyId = string.Format("{0:X8}", BobJenkinsOneAtATimeHash.CalculateHash(DateTime.Now.ToString("yyyyMMddHHmmssfff")));
                this.pluginHost.CustomConfig.SetString(configKeyPinStoreKeyId, keyId);
            }
        }
    }
}