using System;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using EpiSource.KeePass.Ekf.Crypto.Windows;

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
        
        [NonSerialized]
        private KeyInfo privKeyInfo;

        private KeyInfo PrivateKeyInfo {
            get { return this.privKeyInfo ?? (this.privKeyInfo = NativeCapi.QueryCertificatePrivateKey(this.cert)); }
        }
        
        public void GetObjectData(SerializationInfo info, StreamingContext context) {
            info.AddValue("cert", this.cert);
        }

        private WindowsKeyPair(SerializationInfo info, StreamingContext context) {
            var preliminaryCert = (X509Certificate2)info.GetValue("cert", typeof(X509Certificate2));
            
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
        
        private WindowsKeyPair(X509Certificate2 cert, KeyInfo privKeyInfo) {
            this.cert = cert;
            this.privKeyInfo = privKeyInfo;
        }

        public static WindowsKeyPair FromX509Certificate(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, false, false);  
        }
        
        public static WindowsKeyPair FromX509CertificateOrNull(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, false, true);
        }

        public static WindowsKeyPair FromX509CertificateAssumeCspOrNull(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, true, true);
        }

        private static WindowsKeyPair FromX509CertificateInternal(X509Certificate2 cert,
            bool permitLazyKeyInfo, bool nullOnError) {
            
            if (cert == null) {
                if (nullOnError) {
                    return null;
                }
                throw new ArgumentNullException("cert");
            }

            var privateKeyInfo = NativeCapi.QueryCertificatePrivateKey(cert);
            if (permitLazyKeyInfo || privateKeyInfo != null) {
                return new WindowsKeyPair(cert, privateKeyInfo);
            } 
            
            if (nullOnError) {
                return null;
            }
            throw new ArgumentException("Certificate not backed by valid CNG or CSP provider.",
                "cert"); 
        }

        public bool? IsSmartcard {
            get {
                try {
                    return this.PrivateKeyInfo == null ? (bool?) null : this.PrivateKeyInfo.IsHardware;
                } catch (CryptographicException) {
                    return null;
                } 
            }
        }
        
        public bool IsAccessible {
            get { return NativeCapi.IsCertificatePrivateKeyAccessible(this.cert); }
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
                    return this.privKeyInfo == null ? (bool?) null : this.PrivateKeyInfo.IsRemovable;
                } catch (CryptographicException) {
                    return null;
                }
            }
        }
        
        public bool CanDecrypt {
            get {
                return this.PrivateKeyInfo != null && this.cert.HasPrivateKey && this.PrivateKeyInfo.CanDecrypt;
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
                return this.PrivateKeyInfo != null && this.PrivateKeyInfo.CanKeyAgree;
            }
        }

        public bool CanSign {
            get {
                return this.PrivateKeyInfo != null && this.PrivateKeyInfo.CanSign;
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
            get { return this.cert;  }
        }
    }
}