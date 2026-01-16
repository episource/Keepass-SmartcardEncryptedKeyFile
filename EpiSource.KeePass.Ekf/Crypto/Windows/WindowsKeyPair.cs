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

        private KeyInfo pubKeyInfo;

        private bool isPrivKeyAccessible;
        
        public void GetObjectData(SerializationInfo info, StreamingContext context) {
            info.AddValue("cert", this.cert);
            info.AddValue("isPrivKeyAccessible", this.isPrivKeyAccessible);
            info.AddValue("privKeyInfo", this.privKeyInfo);
            info.AddValue("pubKeyInfo", this.pubKeyInfo);
        }

        private WindowsKeyPair(SerializationInfo info, StreamingContext context) {
            var preliminaryCert = (X509Certificate2)info.GetValue("cert", typeof(X509Certificate2));
            this.isPrivKeyAccessible =  info.GetBoolean("isPrivKeyAccessible");
            this.privKeyInfo = (KeyInfo)info.GetValue("privKeyInfo", typeof(KeyInfo));
            this.pubKeyInfo = (KeyInfo)info.GetValue("pubKeyInfo", typeof(KeyInfo));
            
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
            get { return this.isPrivKeyAccessible; }
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

        public bool CanDecryptCms {
            get {
                return this.CanKeyAgree || this.CanKeyTransfer;
            }
        }
        
        public bool CanEncryptCms {
            get {
                return this.pubKeyInfo.CanKeyTransfer || this.pubKeyInfo.CanKeyAgree;
            }
        }

        public bool CanKeyAgree {
            get {
                return this.pubKeyInfo.CanKeyAgree && (this.privKeyInfo == null || this.privKeyInfo.CanKeyAgree);
            }
        }

        public bool CanKeyTransfer {
            get {
                return this.pubKeyInfo.CanKeyTransfer && (this.privKeyInfo == null || this.privKeyInfo.CanKeyTransfer);
            }
        }

        public bool CanSign {
            get {
                return this.pubKeyInfo.CanSign && (this.privKeyInfo == null || this.privKeyInfo.CanSign);
            }
        }
        
        public bool IsReadyForDecryptCms {
            get { return this.CanDecryptCms && this.IsAccessible; }
        }
        
        public bool IsReadyForEncryptCms {
            get { return this.CanEncryptCms; }
        }
        
        public bool IsReadyForSign {
            get { return this.CanSign && this.IsAccessible; }
        }

        public X509Certificate2 Certificate {
            get { return this.cert; }
        }
        
        public bool Refresh() {
            var nextPrivKeyInfo = NativeCapi.QueryCertificatePrivateKey(this.cert);
            var nextPubKeyInfo = NativeCapi.QueryCertificatePublicKey(this.cert);
            var nextIsAccessible = NativeCapi.IsCertificatePrivateKeyAccessible(this.cert);

            if ((nextPrivKeyInfo == null && this.privKeyInfo == null || (nextPrivKeyInfo != null && nextPrivKeyInfo.Equals(this.privKeyInfo)))
                && nextPubKeyInfo.Equals(this.pubKeyInfo) && nextIsAccessible == this.isPrivKeyAccessible) {
                return false;
            }
            
            this.privKeyInfo = nextPrivKeyInfo;
            this.pubKeyInfo = nextPubKeyInfo;
            this.isPrivKeyAccessible = nextIsAccessible;

            return true;
        }
    }
}