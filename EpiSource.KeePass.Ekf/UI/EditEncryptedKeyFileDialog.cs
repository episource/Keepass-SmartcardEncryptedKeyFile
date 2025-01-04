using System;
using System.IO;
using System.Linq;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.KeyProvider;
using EpiSource.KeePass.Ekf.Keys;

using Episource.KeePass.EKF.Resources;

using KeePass.App;
using KeePass.Forms;
using KeePass.Resources;
using KeePass.UI;

using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.UI {
    public partial class EditEncryptedKeyFileDialog {

        private readonly bool permitNewKey;
        private readonly IOConnectionInfo dbPath;
        
        private readonly LiveKeyDataStore activeDbKey;
        private IKeyDataStore nextKey;
        private bool keyWasExported;
        
        private EditEncryptedKeyFileDialog(IOConnectionInfo dbPath, IUserKey activeDbKey, IKeyPairProvider authCandidates, bool permitNewKey) {
            this.dbPath = dbPath;
            this.activeDbKey = activeDbKey == null ? null : new LiveKeyDataStore(activeDbKey);
            this.nextKey = (IKeyDataStore) this.activeDbKey ?? new RandomKeyDataStore();
            this.keyWasExported = false;
            this.permitNewKey = permitNewKey;

            this.InitializeUI();

            // AddKeyIfNew requires UI to be initialized!
            foreach (var keyPair in authCandidates.GetAvailableKeyPairs()) {
                if (!this.AddKeyIfNew(keyPair)) {
                    throw new ArgumentException(
                        @"Duplicated key pair: " + keyPair.KeyPair.Certificate.Thumbprint,
                        "authCandidates");
                }
            }
            
            this.ValidateInput();
        }
       
        public static KeyEncryptionRequest AskForNewEncryptedKeyFile(IOConnectionInfo dbPath, IUserKey activeDbKey) {
            if (dbPath == null) {
                throw new ArgumentNullException("dbPath");
            }
            // activeDbKey is optional - might be new db

            // TODO: DefaultKeyPairProvider constructor blocks if busy HW is involved - unblock
            var dialog = new EditEncryptedKeyFileDialog(dbPath, activeDbKey, new DefaultKeyPairProvider(dbPath), true);
            return dialog.ShowDialogAndGenerateEncryptionRequest();
        }
        
        public static KeyEncryptionRequest AskForSettings(IOConnectionInfo dbPath, IUserKey keyFile) {
            if (dbPath == null) {
                throw new ArgumentNullException("dbPath");
            }
            if (keyFile == null) {
                throw new ArgumentNullException("keyFile");
            }
            if (!CanAskForSettings(keyFile)) { 
                throw new ArgumentException(@"Unsupported key type.", "keyFile"); 
            }
            
            // TODO: DefaultKeyPairProvider constructor blocks if busy HW is involved - unblock
            var dialog = new EditEncryptedKeyFileDialog(dbPath, keyFile, new DefaultKeyPairProvider(dbPath), false);
            return dialog.ShowDialogAndGenerateEncryptionRequest();
        }

        public static bool CanAskForSettings(IUserKey keyFile) {
            return keyFile is KcpKeyFile || keyFile is KcpCustomKey && ((KcpCustomKey) keyFile).Name == SmartcardEncryptedKeyProvider.ProviderName;
        }

        private void ExportKey() {
            if (this.nextKey == null) {
                return;
            }
            
            var saveFileDialog =  UIUtil.CreateSaveFileDialog(KPRes.KeyFileCreate, string.Empty, UIUtil.CreateFileTypeFilter("key", KPRes.KeyFiles, true), 1, "key", AppDefs.FileDialogContext.KeyFile);
            if (saveFileDialog.ShowDialog() != DialogResult.OK) {
                return;
            }

            try {
                this.nextKey.WriteToXmlKeyFile(saveFileDialog.FileName);
            }
            catch (IOException e) {
                MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextFailureExportingKey, e, e.Message, saveFileDialog.FileName),
                    Strings.EditEncryptedKeyFileDialog_DialogTitleFailureExportingKey, 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            
            this.keyWasExported = true;
            this.OnContentChanged();
        }

        private void ImportKey() {
            var openFileDialog = UIUtil.CreateOpenFileDialog(KPRes.KeyFileSelect, UIUtil.CreateFileTypeFilter("key", KPRes.KeyFiles, true), 2, null, false, AppDefs.FileDialogContext.KeyFile);
            if (openFileDialog.ShowDialog() != DialogResult.OK) {
                return;
            }

            if (!File.Exists(openFileDialog.FileName)) {
                MessageBox.Show(string.Format(Strings.Culture, Strings.EdidEncryptedKeyFileDialog_DialogTextFileNotFound, openFileDialog.FileName),
                    Strings.EditEncryptedKeyFileDialog_DialogTitleFileNotFound,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            this.nextKey = new ImportedKeyDataStore(openFileDialog.FileName);
            this.keyWasExported = false;
            
            this.OnContentChanged();
        }

        private void RevertToActiveKey() {
            if (this.activeDbKey == null) {
                return;
            }

            this.nextKey = this.activeDbKey;
            this.keyWasExported = false;
            
            this.OnContentChanged();
        }

        private void GenerateRandomKey() {
            var entropyForm = new EntropyForm();
            var result = entropyForm.ShowDialog(this);
            if (result != DialogResult.OK) {
                return;
            }
            
            this.nextKey = new RandomKeyDataStore(entropyForm.GeneratedEntropy);
            this.keyWasExported = false;
            
            this.OnContentChanged();
        }

        private KeyEncryptionRequest ShowDialogAndGenerateEncryptionRequest() {
            this.ShowDialog();
            if (this.DialogResult != DialogResult.OK) {
                return null;
            }

            var authorizationChanged =
                this.DialogResult == DialogResult.OK ||
                this.keyList.Values
                    .Select(x => x.NextAuthorization != x.CurrentAuthorization)
                    .FirstOrDefault();
            if (!authorizationChanged) {
                return null;
            }

            var selectedKeys =
                this.keyList.Values
                    .Where(x => x.NextAuthorization == KeyPairModel.Authorization.Authorized)
                    .Select(x => x.KeyPair);
            return new KeyEncryptionRequest(this.dbPath, this.nextKey.KeyData, selectedKeys);
        }

        private bool ValidateInput() {
            if (this.keyList.Count == 0) {
                this.ShowValidationError(Strings.EditEncryptedKeyFileDialog_ValidationMessageNoSmartcard);
                return false;
            }

            var requiresExport = this.nextKey is RandomKeyDataStore && !this.keyWasExported;
            if (requiresExport) {
                this.ShowValidationError(Strings.EditEncryptedKeyFileDialog_ValidationMessageKeyNeedsExport);
                return false;
            }

            var anyKeySelected =
                this.keyList.Any(x => x.Value.NextAuthorization == KeyPairModel.Authorization.Authorized);
            if (!anyKeySelected) {
                this.ShowValidationError(Strings.EditEncryptedKeyFileDialog_ValidationMessageSelectSmartcard);
                return false;
            }

            return true;
        }

        private string DescribeKeySource() {
            if (this.nextKey == this.activeDbKey) {
                return Strings.EditEncryptedKeyFileDialog_KeySourceActiveDb;
            } 
            if (this.nextKey is RandomKeyDataStore) {
                return Strings.EditEncryptedKeyFileDialog_KeySourceRandom;
            }

            var importedKey = this.nextKey as ImportedKeyDataStore;
            if (importedKey != null) {
                return string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_KeySourceImported,
                    importedKey.FileName);
            }
            
            return Strings.EditEncryptedKeyFileDialog_KeySourceUnknown;
        }
    }
}