using System;
using System.Runtime.CompilerServices;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.Plugin;
using EpiSource.Unblocker.Util;

using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed partial class EditEncryptedKeyFileDialogFactory {
        
        private readonly UIFactory uiFactory;
        
        public EditEncryptedKeyFileDialogFactory(UIFactory uiFactory) {
            this.uiFactory = uiFactory;
        }
        
        public KeyEncryptionRequest AskForNewEncryptedKeyFile(IOConnectionInfo dbPath, IUserKey activeDbKey) {
            if (dbPath == null) {
                throw new ArgumentNullException("dbPath");
            }
            // activeDbKey is optional - might be new db

            // Note: DefaultKeyPairProvider#FromDbPath constructor blocks if busy HW is involved - unblock
            var keyPairProvider = this.uiFactory.SmartcardOperationDialog.DoCryptoWithMessagePumpShort(ct => DefaultKeyPairProvider.FromSystemKeyStore());

            var dialog = new EditEncryptedKeyFileDialog(dbPath, activeDbKey, keyPairProvider, true);
            return dialog.ShowDialogAndGenerateEncryptionRequest();
        }

        public KeyEncryptionRequest AskForSettings(IOConnectionInfo dbPath, IUserKey keyFile) {
            if (dbPath == null) {
                throw new ArgumentNullException("dbPath");
            }
            if (keyFile == null) {
                throw new ArgumentNullException("keyFile");
            }
            if (!CanAskForSettings(keyFile)) {
                throw new ArgumentException(@"Unsupported key type.", "keyFile");
            }

            // IOConnection not serializable - need to read file outside unblocker task
            var ekfPath = dbPath.ResolveEncryptedKeyFile();
            var encryptedKeyFileData = IOConnection.OpenRead(ekfPath).ReadAllBinaryAndClose();

            // Note: DefaultKeyPairProvider#FromDbPath constructor blocks if busy HW is involved - unblock
            var keyPairProvider = this.uiFactory.SmartcardOperationDialog.DoCryptoWithMessagePumpShort(ct => DefaultKeyPairProvider.FromEncryptedKeyFileBinary(encryptedKeyFileData));

            var dialog = new EditEncryptedKeyFileDialog(dbPath, keyFile, keyPairProvider, false);
            return dialog.ShowDialogAndGenerateEncryptionRequest();
        }

        public bool CanAskForSettings(IUserKey keyFile) {
            return keyFile is KcpKeyFile || keyFile is KcpCustomKey && ((KcpCustomKey) keyFile).Name == SmartcardEncryptedKeyProvider.ProviderName;
        }
    }
}