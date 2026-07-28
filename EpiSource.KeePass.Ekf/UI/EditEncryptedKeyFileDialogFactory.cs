using System;
using System.IO;
using System.Runtime.CompilerServices;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.Plugin;
using EpiSource.Unblocker.Util;

using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed partial class EditEncryptedKeyFileDialogFactory {
        
        private readonly UIFactory uiFactory;
        
        public EditEncryptedKeyFileDialogFactory(UIFactory uiFactory) {
            this.uiFactory = uiFactory;
        }
        
        public KeyEncryptionRequest AskForNewEncryptedKeyFile(IOConnectionInfo dbPath, PwDatabase dbOrNull) {
            if (dbPath == null) {
                throw new ArgumentNullException("dbPath");
            }
            if (dbOrNull != null && !string.Equals(dbPath.Path, dbOrNull.IOConnectionInfo.Path, StringComparison.InvariantCultureIgnoreCase)) {
                throw new ArgumentException("dbOrNull has different path");
            }

            // activeDbKey is optional - might be new db
            var activeDbKey = dbOrNull.GetEkfKey();
            if (activeDbKey != null & !this.CanAskForSettings(activeDbKey)) {
                activeDbKey = null;
            }

            IKeyPairProvider keyPairProvider;
            if (dbOrNull != null && activeDbKey != null) {
                var ekfStore = new EkfStore(dbOrNull, this.uiFactory.PluginConfiguration);
                keyPairProvider = ekfStore.ReadAsKeyProvider(this.uiFactory);
            } else {
                // Note: DefaultKeyPairProvider#FromDbPath constructor blocks if busy HW is involved - unblock
                keyPairProvider = this.uiFactory.SmartcardOperationDialog
                        .DoCryptoWithMessagePumpShort(ct => DefaultKeyPairProvider.FromSystemKeyStore());
            }

            var dialog = new EditEncryptedKeyFileDialog(dbPath, activeDbKey, keyPairProvider, true, this.uiFactory);
            return dialog.ShowDialogAndGenerateEncryptionRequest();
        }

        public KeyEncryptionRequest AskForSettings(PwDatabase db, IUserKey keyFile) {
            if (db == null || ! db.IsOpen) {
                throw new ArgumentException("db is null or not open");
            }
            if (keyFile == null) {
                throw new ArgumentNullException("keyFile");
            }
            if (!this.CanAskForSettings(keyFile)) {
                throw new ArgumentException(@"Unsupported key type.", "keyFile");
            }

            var ekfStore = new EkfStore(db, this.uiFactory.PluginConfiguration);
            var keyPairProvider = ekfStore.ReadAsKeyProvider(this.uiFactory);

            var dialog = new EditEncryptedKeyFileDialog(db.IOConnectionInfo,keyFile, keyPairProvider, false, this.uiFactory);
            return dialog.ShowDialogAndGenerateEncryptionRequest();
        }

        public bool CanAskForSettings(IUserKey keyFile) {
            return keyFile is KcpCustomKey && ((KcpCustomKey) keyFile).Name == SmartcardEncryptedKeyProvider.ProviderName;
        }

    }
}