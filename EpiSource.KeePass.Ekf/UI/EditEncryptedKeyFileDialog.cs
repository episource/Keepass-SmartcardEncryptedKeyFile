using System;
using System.IO;
using System.Linq;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.Keys;
using EpiSource.KeePass.Ekf.Plugin;

using Episource.KeePass.EKF.Resources;

using EpiSource.Unblocker.Util;

using KeePass.App;
using KeePass.Forms;
using KeePass.Resources;
using KeePass.UI;

using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed partial class EditEncryptedKeyFileDialogFactory {
        private sealed partial class EditEncryptedKeyFileDialog {

            private readonly bool permitNewKey;
            private readonly IOConnectionInfo dbPath;

            private readonly LiveKeyDataStore activeDbKey;
            private IKeyDataStore nextKey;
            private bool keyWasExported;

            internal EditEncryptedKeyFileDialog(IOConnectionInfo dbPath, IUserKey activeDbKey, IKeyPairProvider authCandidates, bool permitNewKey) {
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

            private void ExportKey() {
                if (this.nextKey == null) {
                    return;
                }

                var saveFileDialog = UIUtil.CreateSaveFileDialog(KPRes.KeyFileCreate, string.Empty, UIUtil.CreateFileTypeFilter("keyx", KPRes.KeyFiles, true), 1, "key", AppDefs.FileDialogContext.KeyFile);
                if (saveFileDialog.ShowDialog() != DialogResult.OK) {
                    return;
                }

                try {
                    using (var s = File.Open(saveFileDialog.FileName, FileMode.Create, FileAccess.Write)) {
                        const ulong v2 = 0x0002000000000000;
                        KfxFile.Create(v2, this.nextKey.KeyData.ReadData(), null).Save(s);
                    }
                } catch (IOException e) {
                    MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextFailureExportingKey, e, e.Message, saveFileDialog.FileName),
                        Strings.EditEncryptedKeyFileDialog_DialogTitleFailureExportingKey,
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                this.keyWasExported = true;
                this.OnContentChanged();
            }

            private void ImportKey() {
                var openFileDialog = UIUtil.CreateOpenFileDialog(KPRes.KeyFileSelect, UIUtil.CreateFileTypeFilter("key|keyx", KPRes.KeyFiles, true), 2, null, false, AppDefs.FileDialogContext.KeyFile);
                if (openFileDialog.ShowDialog() != DialogResult.OK) {
                    return;
                }

                if (!File.Exists(openFileDialog.FileName)) {
                    MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextFileNotFound, openFileDialog.FileName),
                        Strings.EditEncryptedKeyFileDialog_DialogTitleFileNotFound,
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var importedKey = ImportedKeyDataStore.FromKfxFile(openFileDialog.FileName);
                if (importedKey == null) {
                    var result = MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextNoXmlKeyFile, openFileDialog.FileName),
                        Strings.EditEncryptedKeyFileDialog_DialogTitleNoXmlKeyFile,
                        MessageBoxButtons.YesNo, MessageBoxIcon.Information);

                    if (result == DialogResult.No) return;

                    importedKey = ImportedKeyDataStore.FromPlainKeyFile(openFileDialog.FileName);
                }
                if (importedKey == null) {
                    MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextInvalidPlainKeyFile, openFileDialog.FileName),
                        Strings.EditEncryptedKeyFileDialog_DialogTitleInvalidPlainKeyFile,
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                this.nextKey = importedKey;
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

            internal KeyEncryptionRequest ShowDialogAndGenerateEncryptionRequest() {
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
}