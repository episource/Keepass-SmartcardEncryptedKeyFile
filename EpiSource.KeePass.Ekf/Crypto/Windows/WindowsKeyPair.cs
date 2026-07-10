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
        
        private X509KeyUsageFlags keyUsageFlags;
        
        public void GetObjectData(SerializationInfo info, StreamingContext context) {
            info.AddValue("cert", this.cert);
            info.AddValue("privKeyInfo", this.privKeyInfo);
            info.AddValue("pubKeyInfo", this.pubKeyInfo);
        }

        private WindowsKeyPair(SerializationInfo info, StreamingContext context) {
            var preliminaryCert = (X509Certificate2)info.GetValue("cert", typeof(X509Certificate2));
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
            
            this.UpdateKeyUsageFlags();
        }
        
        private WindowsKeyPair(X509Certificate2 cert) {
            this.cert = cert;
            this.UpdateKeyUsageFlags();
        }

        private void UpdateKeyUsageFlags() {
            this.keyUsageFlags = this.cert.Extensions
                .OfType<X509KeyUsageExtension>()
                .Select(usage => usage.KeyUsages)
                .DefaultIfEmpty(~X509KeyUsageFlags.None)
                .FirstOrDefault();
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
            get { return this.privKeyInfo != null && this.privKeyInfo.IsAccessible && this.pubKeyInfo != null && this.pubKeyInfo.IsAccessible; }
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
                return this.CanKeyAgree || this.CanKeyTransfer;
            }
        }

        // Key usage flags asserting the certificate may be used for CMS encryption/decryption.
        // Besides the standard RSA keyEncipherment and (EC)DH keyAgreement bits, some smartcards
        // (e.g. PIV cards) mark their encryption certificate with dataEncipherment instead of
        // keyEncipherment. Gate on any of these bits and let the key algorithm (pubKeyInfo) decide
        // between key transfer and key agreement - requiring an exact bit per primitive locks out
        // otherwise valid encryption keys (see issue #12). Absent a key usage extension all bits are
        // assumed set (see UpdateKeyUsageFlags), so unrestricted certificates keep working.
        private const X509KeyUsageFlags encryptionKeyUsage =
            X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyAgreement;

        private bool KeyUsageAllowsEncryption {
            get { return (this.keyUsageFlags & encryptionKeyUsage) != X509KeyUsageFlags.None; }
        }

        public bool CanKeyAgree {
            get {
                return this.KeyUsageAllowsEncryption
                        && this.pubKeyInfo.CanKeyAgree && (this.privKeyInfo == null || this.privKeyInfo.CanKeyAgree);
            }
        }

        public bool CanKeyTransfer {
            get {
                return this.KeyUsageAllowsEncryption
                        && this.pubKeyInfo.CanKeyTransfer && (this.privKeyInfo == null || this.privKeyInfo.CanKeyTransfer);
            }
        }

        public bool CanSign {
            get {
                return (this.keyUsageFlags & X509KeyUsageFlags.DigitalSignature) == X509KeyUsageFlags.DigitalSignature
                        && this.pubKeyInfo.CanSign && (this.privKeyInfo == null || this.privKeyInfo.CanSign);
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

            if ((nextPrivKeyInfo == null && this.privKeyInfo == null || (nextPrivKeyInfo != null && nextPrivKeyInfo.Equals(this.privKeyInfo)))
                && nextPubKeyInfo.Equals(this.pubKeyInfo)) {
                return false;
            }
            
            this.privKeyInfo = nextPrivKeyInfo;
            this.pubKeyInfo = nextPubKeyInfo;
            
            this.UpdateKeyUsageFlags();

            return true;
        }
    }
}