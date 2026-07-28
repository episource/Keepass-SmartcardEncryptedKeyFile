using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Net;

using EpiSource.KeePass.Ekf.Crypto;
using EpiSource.KeePass.Ekf.UI;
using EpiSource.Unblocker.Util;

using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Serialization;

namespace EpiSource.KeePass.Ekf.Plugin {
    public class EkfStore {
        public const string EkfExtension = ".ekf";
        public const string EkfPublicCustomDataHeaderKey = "EpiSource.KeePass.Ekf.EmbeddedEkfData";
        private const string BackupExtension = ".bak";
        
        private readonly PwDatabase db;
        private readonly PluginConfiguration config;

        public EkfStore(IOConnectionInfo dbPath, PluginConfiguration config) 
            : this(PwDatabase.LoadHeader(dbPath), config) {
        }
        
        public EkfStore(PwDatabase db, PluginConfiguration config) {
            if (db == null) {
                throw new ArgumentNullException("db");
            }
            if (config == null) {
                throw new ArgumentNullException("config");
            }
            
            this.db = db;
            this.config = config;
        }

        /// <summary>
        /// Blocking, but pumps UI message loop!
        /// </summary>
        public EncryptedKeyFile Read(UIFactory uiFactory) {
            // IOConnectionInfo not serializable -> read outside unblocker process!
            var encodedEkf = this.ReadEncoded();
            if (encodedEkf == null) {
                return null;
            }
            
            // EncryptedKeyFile.Read/Decode blocks if busy HW is involved
            return uiFactory.SmartcardOperationDialog
                    .DoCryptoWithMessagePumpShort(ct => EncryptedKeyFile.Decode(encodedEkf));
        }
        
        /// <summary>
        /// Blocking, but pumps UI message loop!
        /// </summary>
        public IKeyPairProvider ReadAsKeyProvider(UIFactory uiFactory) {
            // IOConnectionInfo not serializable -> read outside unblocker process!
            var encodedEkf = this.ReadEncoded();
            if (encodedEkf == null) {
                return null;
            }
            
            // Note: DefaultKeyPairProvider#FromDbPath constructor blocks if busy HW is involved - unblock
            return  uiFactory.SmartcardOperationDialog.DoCryptoWithMessagePumpShort(ct => DefaultKeyPairProvider.FromEncryptedKeyFileBinary(encodedEkf));
        }
        
        public byte[] ReadEncoded() {
            var storeReadOrder = 
                this.config.PreferredEkfStore == EkfStorePrecedence.EXTERNAL
                    ? new List<EkfStorePrecedence> { EkfStorePrecedence.EXTERNAL, EkfStorePrecedence.KDBX }
                    : new List<EkfStorePrecedence> { EkfStorePrecedence.KDBX, EkfStorePrecedence.EXTERNAL };
            
            foreach (var source in storeReadOrder) {
                var encodedEkf = source == EkfStorePrecedence.KDBX ? this.ReadEncodedEmbeddedEkf() : this.ReadEncodedExternalEkf();
                if (encodedEkf != null) {
                    return encodedEkf;
                }
            }

            return null;
        }

        public void Write(KeyEncryptionRequest keyEncryptionRequest) {
            if (this.db == null || !this.db.IsOpen) {
                throw new ArgumentException("db is null or not open");
            }
            var dbKeyFile = this.db.GetEkfKey();
            if (dbKeyFile == null || !dbKeyFile.KeyData.Equals(keyEncryptionRequest.VirtualKeyFile.KeyData)) {
                throw new ArgumentException("The given db cannot be unlocked with the supplied key material.");
            }

            this.Write(keyEncryptionRequest.Encrypt(this.config.StrictRfc5753));
        }

        public void Write(EncryptedKeyFile encryptedKeyFile) {
            if (this.db == null || !this.db.IsOpen) {
                throw new ArgumentException("db is null or not open");
            }
            
            if (this.config.PreferredEkfStore == EkfStorePrecedence.EXTERNAL) {
                this.WriteExternalEkf(encryptedKeyFile);
            } else {
                this.WriteEmbeddedEkf(encryptedKeyFile);
            }
        }

        private void WriteExternalEkf(EncryptedKeyFile ekf) {
            using (var stream = IOConnection.OpenWrite(this.ResolveExternalEkf())) {
                ekf.Write(stream);
            }
            
            var embeddedEkf = this.db.PublicCustomData.GetByteArray(EkfPublicCustomDataHeaderKey);
            if (embeddedEkf == null) {
                return;
            }
            
            // do not delete key, it would be restored on db sync; instead write empty data
            this.db.PublicCustomData.SetByteArray(EkfPublicCustomDataHeaderKey, new byte[]{});
            
            // mark the database as changed (allow save) and set changed date (for proper kdbx sync)
            this.db.Modified = true;
            this.db.SettingsChanged = DateTime.Now;
        }

        private void WriteEmbeddedEkf(EncryptedKeyFile ekf) {
            if (!this.db.IsOpen || this.db.MasterKey.UserKeyCount == 0) {
                // database has not been opened or only headers were loaded
                throw new InvalidOperationException("The database is not loaded.");
            }
            
            this.db.PublicCustomData.SetByteArray(EkfPublicCustomDataHeaderKey, ekf.Encode());
            
            // mark the database as changed (allow save) and set changed date (for proper kdbx sync)
            this.db.Modified = true;
            this.db.SettingsChanged = DateTime.Now;
            
            var externalEkf = this.ResolveExternalEkf();
            if (externalEkf == null || !IOConnection.FileExists(externalEkf)) {
                return;
            }

            try {
                IOConnection.RenameFile(externalEkf, this.AddBackupExtension(externalEkf));
            } catch (IOException) {
                // continue silently
            }
        }
        
        private byte[] ReadEncodedExternalEkf() {
            if (this.db == null) {
                return null;
            }
            
            var ekfPath = this.ResolveExternalEkf();
            if (!IOConnection.FileExists(ekfPath)) {
                return null;
            }
            
            return IOConnection.OpenRead(ekfPath).ReadAllBinaryAndClose();
        }

        private byte[] ReadEncodedEmbeddedEkf() {
            if (this.db == null || !this.db.IsOpen) {
                return null;
            }
            
            var publicDataHeader = this.db.PublicCustomData;
            var embeddedEkf = publicDataHeader.GetByteArray(EkfPublicCustomDataHeaderKey);

            // instead of deleting the custom data item, an empty byte[] is stored to mark
            // the item as deleted (db sync would else restore the ekf from the one db still
            // containing ekf data)
            if (embeddedEkf == null || embeddedEkf.Length == 0) {
                return null;
            }

            return embeddedEkf;
        }

        private IOConnectionInfo ResolveExternalEkf() {
            if (this.db.IOConnectionInfo.ToString().EndsWith(EkfExtension)) {
                return this.db.IOConnectionInfo;
            } else {
                var ekfPath = this.db.IOConnectionInfo.CloneDeep();
                ekfPath.Path += EkfExtension;
                return ekfPath;
            }
        }

        private IOConnectionInfo AddBackupExtension(IOConnectionInfo path) {
            if (path.ToString().EndsWith(BackupExtension)) {
                return path;
            } else {
                var backupPath = path.CloneDeep();
                backupPath.Path += BackupExtension;
                return backupPath;
            }
        }
    }
}