using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.Keys;
using EpiSource.KeePass.Ekf.Plugin;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.UI.Windows;
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
            private readonly string defaultKeyFileName;

            private readonly LiveKeyDataStore activeDbKey;
            private IKeyDataStore nextKey;
            private bool keyWasExported;

            internal EditEncryptedKeyFileDialog(IOConnectionInfo dbPath, IUserKey activeDbKey, IKeyPairProvider authCandidates, bool permitNewKey) {
                this.dbPath = dbPath;
                this.defaultKeyFileName = Path.GetFileName(dbPath.Path) + ".keyx";
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

                var exportKeyFile = this.ShowSaveFileDialog();
                if (exportKeyFile == null) {
                    return;
                }
                
                try {
                    if (File.Exists(exportKeyFile) && File.GetAttributes(exportKeyFile).HasFlag(FileAttributes.Directory)) {
                        exportKeyFile = Path.Combine(exportKeyFile, this.defaultKeyFileName);
                    }
                    
                    using (var s = File.Open(exportKeyFile, FileMode.Create, FileAccess.Write)) {
                        const ulong v2 = 0x0002000000000000;
                        KfxFile.Create(v2, this.nextKey.KeyData.ReadData(), null).Save(s);
                    }
                } catch (IOException e) {
                    MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextFailureExportingKey, e, e.Message, exportKeyFile),
                        Strings.EditEncryptedKeyFileDialog_DialogTitleFailureExportingKey,
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                this.keyWasExported = true;
                this.OnContentChanged();
            }

            private void ImportKey() {
                var importKeyFile = this.ShowOpenFileDialog();
                if (importKeyFile == null) {
                    return;
                }

                if (!File.Exists(importKeyFile)) {
                    MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextFileNotFound, importKeyFile),
                        Strings.EditEncryptedKeyFileDialog_DialogTitleFileNotFound,
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var importedKey = ImportedKeyDataStore.FromKfxFile(importKeyFile);
                if (importedKey == null) {
                    var result = MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextNoXmlKeyFile, importKeyFile),
                        Strings.EditEncryptedKeyFileDialog_DialogTitleNoXmlKeyFile,
                        MessageBoxButtons.YesNo, MessageBoxIcon.Information);

                    if (result == DialogResult.No) return;

                    importedKey = ImportedKeyDataStore.FromPlainKeyFile(importKeyFile);
                }
                if (importedKey == null) {
                    MessageBox.Show(string.Format(Strings.Culture, Strings.EditEncryptedKeyFileDialog_DialogTextInvalidPlainKeyFile, importKeyFile),
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

            private string ShowOpenFileDialog() {
                return ShowFileDialog(false);
            }

            private string ShowSaveFileDialog() {
                return ShowFileDialog(true);
            }

            private string ShowFileDialog(bool isSave) {
                if (!NativeForms.IsOnDefaultDesktop(this)) {
                    var keepassMinimalisticFileDialog = new FileBrowserForm();

                    try {
                        keepassMinimalisticFileDialog.InitEx(isSave, isSave ? KPRes.KeyFileCreate : KPRes.KeyFileSelect, KPRes.SecDeskFileDialogHint, AppDefs.FileDialogContext.KeyFile);
                        keepassMinimalisticFileDialog.SuggestedFile = this.defaultKeyFileName;

                        return keepassMinimalisticFileDialog.ShowDialog(this) == DialogResult.OK ? keepassMinimalisticFileDialog.SelectedFile : null;
                    } finally {
                        UIUtil.DestroyForm(keepassMinimalisticFileDialog);    
                    }
                }

                var nativeFileDialog = isSave
                    ? (FileDialogEx)UIUtil.CreateSaveFileDialog(KPRes.KeyFileCreate, string.Empty, UIUtil.CreateFileTypeFilter("keyx", KPRes.KeyFiles, true), 1, "key", AppDefs.FileDialogContext.KeyFile)
                    : (FileDialogEx)UIUtil.CreateOpenFileDialog(KPRes.KeyFileSelect, UIUtil.CreateFileTypeFilter("key|keyx", KPRes.KeyFiles, true), 2, null, false, AppDefs.FileDialogContext.KeyFile);
                return nativeFileDialog.ShowDialog(this) == DialogResult.OK ? nativeFileDialog.FileName : null;
            }
        }
    }
}