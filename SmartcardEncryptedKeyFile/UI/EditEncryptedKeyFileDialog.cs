using System;
using System.IO;
using System.Linq;
using System.Windows.Forms;

using Episource.KeePass.Ekf.KeyProvider;
using Episource.KeePass.EKF.Crypto;

using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace Episource.KeePass.EKF.UI {
    public partial class EditEncryptedKeyFileDialog {
        private EditEncryptedKeyFileDialog(IOConnectionInfo dbPath, IUserKey existingKey, IKeyPairProvider authCandidates) {
            this.dbPath = dbPath;
            this.keyFile = existingKey;

            var customKey = existingKey as KcpCustomKey;
            if (existingKey == null) {
                this.keyFileDescription = "Random Key";
            } else if (existingKey is KcpKeyFile) {
                this.keyFileDescription = "Current Plaintext Key File";
            } else if (customKey != null && customKey.Name == SmartcardEncryptedKeyProvider.ProviderName) {
                this.keyFileDescription = "Current Encrypted Key File";
            } else {
              throw new ArgumentException(message: "Unsupported existing key type", paramName: "existingKey");  
            }
            
            this.InitializeUI();
            
            foreach (var keyPair in authCandidates.GetAvailableKeyPairs()) {
                if (!this.AddKeyIfNew(keyPair)) {
                    throw new ArgumentException(
                        message: "Duplicated key pair: " + keyPair.KeyPair.Certificate.Thumbprint,
                        paramName: "authCandidates");
                } 
            }

            this.Validate();
        }
       
        public static KeyEncryptionRequest AskForNewEncryptedKeyFile(IOConnectionInfo dbPath) {
            if (dbPath == null) {
                throw new ArgumentNullException(paramName: "dbPath");
            }

            var dialog = new EditEncryptedKeyFileDialog(dbPath, existingKey: null,
                authCandidates: new DefaultKeyPairProvider(dbPath));
            if (dialog.ShowDialog() == DialogResult.OK) {
                return dialog.GenerateEncryptionRequest();
            }
            
            return null;
        }
        
        public static KeyEncryptionRequest AskForAuthorization(IOConnectionInfo dbPath, IUserKey keyFile) {
            if (dbPath == null) {
                throw new ArgumentNullException(paramName: "dbPath");
            }
            if (keyFile == null) {
                throw new ArgumentNullException(paramName: "keyFile");
            }
            
            var dialog = new EditEncryptedKeyFileDialog(dbPath, keyFile, new DefaultKeyPairProvider(dbPath));
            if (dialog.ShowDialog() == DialogResult.OK) {
                return dialog.GenerateEncryptionRequest();
            }
            
            return null;
        }

        private byte[] GenerateRandomKey() {
            using (var ms = new MemoryStream())
            using (var msWriter = new BinaryWriter(ms)) {
                foreach (var keyPairModel in this.keyList.Values) {
                    var cert = keyPairModel.KeyPair.Certificate;
                    msWriter.Write(cert.Thumbprint);
                }
                msWriter.Write(CryptoRandom.Instance.GetRandomBytes(uRequestedBytes: 32));

                return CryptoUtil.HashSha256(ms.ToArray());
            }
        }

        private KeyEncryptionRequest GenerateEncryptionRequest() {
            if (this.DialogResult != DialogResult.OK) {
                throw new InvalidOperationException(message: "Dialog result is not OK");
            }
            
            if (this.keyFile == null) {
                return new KeyEncryptionRequest(this.dbPath, this.GenerateRandomKey(), this.GetSelectedKeyPairs());
            } else {
                return new KeyEncryptionRequest(this.dbPath, this.keyFile.KeyData, this.GetSelectedKeyPairs());
            }
        }
        
        private bool Validate() {
            if (this.keyList.Count == 0) {
                this.ShowValidationError(message: "No smartcard found.");
                return false;        
            }

            var anyKeySelected =
                this.keyList.Any(x => x.Value.NextAuthorization == KeyPairModel.Authorization.Authorized);
            if (!anyKeySelected) {
                this.ShowValidationError(message: "Please select at least one smart card.");
                return false;
            }

            return true;
        }

        private string FormatAuthorization(KeyPairModel.Authorization auth) {
            switch (auth) {
                case KeyPairModel.Authorization.Authorized:
                    return "authorized";
                case KeyPairModel.Authorization.Rejected:
                    return "rejected";
                default:
                    throw new ArgumentOutOfRangeException(paramName: "auth");
                    
            }
        }

        private string FormatKeyProvider(KeyPairModel.KeyProvider keySource) {
            switch (keySource) {
                case KeyPairModel.KeyProvider.Piv:
                    return "PIV / Windows";
                case KeyPairModel.KeyProvider.OpenPGP:
                    return "OpenPGP Card";
                case KeyPairModel.KeyProvider.HbciRdhCard:
                    return "HBCI / RDH Card";
                case KeyPairModel.KeyProvider.EkfAuthorizationList:
                    return "unknown / EKF";
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }
}