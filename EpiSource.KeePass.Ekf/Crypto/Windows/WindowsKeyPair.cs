using System;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    /// <summary>
    /// Gives access to PKCS smart cards that are compatible with the windows CNG or CSP framework.
    /// </summary>
    /// <remarks>
    /// Operations on the private key may block for noticable time, when the private key is backed by a hardware device
    /// (e.g. smartcard). A good example is querying a yubikey, that is still in use by an other operation.
    /// </remarks>
    [Serializable]
    // ReSharper disable once InconsistentNaming
    public sealed class WindowsKeyPair : IKeyPair, ISerializable {

        private X509Certificate2 cert;
        
        private KeyInfo privKeyInfo;

        private bool isAccessible;
        
        public void GetObjectData(SerializationInfo info, StreamingContext context) {
            info.AddValue("cert", this.cert);
            info.AddValue("isAccessible", this.isAccessible);
            info.AddValue("privKeyInfo", this.privKeyInfo);
        }

        private WindowsKeyPair(SerializationInfo info, StreamingContext context) {
            var preliminaryCert = (X509Certificate2)info.GetValue("cert", typeof(X509Certificate2));
            this.privKeyInfo = (KeyInfo)info.GetValue("privKeyInfo", typeof(KeyInfo));
            this.isAccessible =  info.GetBoolean("isAccessible");
            
            using (var userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine)) {
                userStore.Open(OpenFlags.ReadOnly);
                machineStore.Open(OpenFlags.ReadOnly);

                var userStoreCerts = userStore.Certificates.Cast<X509Certificate2>();
                var machineStoreCerts = machineStore.Certificates.Cast<X509Certificate2>();

                var matchingCert = Enumerable.Concat(userStoreCerts, machineStoreCerts)
                          .FirstOrDefault(c => c.Thumbprint == preliminaryCert.Thumbprint);
                
                this.cert = matchingCert ?? preliminaryCert;
            }
        }
        
        private WindowsKeyPair(X509Certificate2 cert) {
            this.cert = cert;
        }

        public static WindowsKeyPair FromX509Certificate(X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException("cert");
            }

            var kp = new WindowsKeyPair(cert);
            kp.Refresh();
            return kp;
        }

        public bool? IsSmartcard {
            get {
                try {
                    return this.privKeyInfo == null ? (bool?) null : this.privKeyInfo.IsHardware;
                } catch (CryptographicException) {
                    return null;
                } 
            }
        }
        
        public bool IsAccessible {
            get { return this.isAccessible; }
        }
        public bool? CanExportPrivateKey {
            get {
                var info = this.privKeyInfo;
                if (info == null) {
                    return null;
                }

                try {
                    return this.cert.HasPrivateKey && info.CanExport;
                } catch (CryptographicException) {
                    return null;
                }
            }
        }
        public bool? IsRemovable {
            get {
                try {
                    return this.privKeyInfo == null ? (bool?) null : this.privKeyInfo.IsRemovable;
                } catch (CryptographicException) {
                    return null;
                }
            }
        }
        
        public bool CanDecrypt {
            get {
                return this.privKeyInfo != null && this.cert.HasPrivateKey && this.privKeyInfo.CanDecrypt;
            }
        }

        public bool CanDecryptCms {
            get {
                return this.CanDecrypt || this.CanKeyAgree;
            }
        }

        public bool CanEncrypt {
            get {
                return this.CanDecrypt;
            }
        }
        
        public bool CanEncryptCms {
            get {
                return this.CanEncrypt || this.CanKeyAgree;
            }
        }

        public bool CanKeyAgree {
            get {
                return this.privKeyInfo != null && this.privKeyInfo.CanKeyAgree;
            }
        }

        public bool CanSign {
            get {
                return this.privKeyInfo != null && this.privKeyInfo.CanSign;
            }
        }

        public bool IsReadyForDecrypt {
            get { return this.CanDecrypt && this.IsAccessible; }
        }
        
        public bool IsReadyForDecryptCms {
            get { return this.CanDecryptCms && this.IsAccessible; }
        }
        
        public bool IsReadyForEncrypt {
            get { return this.CanEncrypt && this.IsAccessible; }
        }
        
        public bool IsReadyForEncryptCms {
            get { return this.CanEncryptCms && this.IsAccessible; }
        }
        
        public bool IsReadyForSign {
            get { return this.CanSign && this.IsAccessible; }
        }

        public X509Certificate2 Certificate {
            get { return this.cert; }
        }
        
        public bool Refresh() {
            var nextPrivKeyInfo = NativeCapi.QueryCertificatePrivateKey(this.cert);
            var nextIsAccessible = NativeCapi.IsCertificatePrivateKeyAccessible(this.cert);

            if (nextPrivKeyInfo.Equals(this.privKeyInfo) && nextIsAccessible == this.isAccessible) {
                return false;
            }
            
            this.privKeyInfo = NativeCapi.QueryCertificatePrivateKey(this.cert);
            this.isAccessible = NativeCapi.IsCertificatePrivateKeyAccessible(this.cert);

            return true;
        }
    }
}