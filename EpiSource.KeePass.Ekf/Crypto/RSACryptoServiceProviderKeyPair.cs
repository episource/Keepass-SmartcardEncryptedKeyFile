using System;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms.VisualStyles;

using EpiSource.KeePass.Ekf.Util.Windows;

namespace EpiSource.KeePass.Ekf.Util {
    /// <summary>
    /// Gives access to RSA smart cards that are compatible with the windows crypto service provider framework.
    /// </summary>
    /// <remarks>
    /// Operations on the private key may block for noticable time, when the private key is backed by a hardware device
    /// (e.g. smartcard). A good example is querying a yubikey, that is still in use by an other operation.
    /// </remarks>
    [Serializable]
    // ReSharper disable once InconsistentNaming
    public sealed class RSACryptoServiceProviderKeyPair : IKeyPair, ISerializable {

        private X509Certificate2 cert;
        
        [NonSerialized]
        private CspKeyContainerInfo privKeyInfo;

        [NonSerialized]
        private CspKeyContainerInfo pubKeyInfo;

        private CspKeyContainerInfo PrivateKeyInfo {
            get { return this.privKeyInfo ?? (this.privKeyInfo = GetPrivateKeyContainerInfoFromCert(this.cert)); }
        }

        private CspKeyContainerInfo PublicKeyInfo {
            get { return this.pubKeyInfo ?? (this.pubKeyInfo = GetPublicKeyContainerInfoFromCert(this.cert)); }
        }
        
        public void GetObjectData(SerializationInfo info, StreamingContext context) {
            info.AddValue("cert", this.cert);
        }

        private RSACryptoServiceProviderKeyPair(SerializationInfo info, StreamingContext context) {
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
        
        private RSACryptoServiceProviderKeyPair(X509Certificate2 cert, CspKeyContainerInfo privKeyInfo, CspKeyContainerInfo pubKeyInfo) {
            this.cert = cert;
            this.privKeyInfo = privKeyInfo;
            this.pubKeyInfo = pubKeyInfo;
        }
        
        

        public static RSACryptoServiceProviderKeyPair FromX509Certificate(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, false, false);  
        }
        
        public static RSACryptoServiceProviderKeyPair FromX509CertificateOrNull(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, false, true);
        }

        public static RSACryptoServiceProviderKeyPair FromX509CertificateAssumeCspOrNull(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, true, true);
        }

        private static RSACryptoServiceProviderKeyPair FromX509CertificateInternal(X509Certificate2 cert,
            bool permitLazyCspInfo, bool nullOnError) {
            
            if (cert == null) {
                if (nullOnError) {
                    return null;
                }
                throw new ArgumentNullException("cert");
            }

            bool isRsa;
            try {
                isRsa = cert.PublicKey.Key is RSA;
            } catch (NotSupportedException) {
                isRsa = false;
            }
            
            if (!isRsa) {
                if (nullOnError) {
                    return null;
                }
                throw new ArgumentException("Not an RSA based certificate.",  "cert");
            }

            var privateKeyInfo = GetPrivateKeyContainerInfoFromCert(cert);
            var publicKeyInfo = GetPublicKeyContainerInfoFromCert(cert);
            if (permitLazyCspInfo || (privateKeyInfo != null && publicKeyInfo != null)) {
                return new RSACryptoServiceProviderKeyPair(cert, privateKeyInfo, publicKeyInfo);
            } 
            
            if (nullOnError) {
                return null;
            }
            throw new ArgumentException("Certificate not backed by windows crypto service provider.",
                "cert"); 
        }

        public bool? IsSmartcard {
            get {
                try {
                    return this.PrivateKeyInfo == null ? (bool?) null : this.PrivateKeyInfo.HardwareDevice;
                } catch (CryptographicException) {
                    return null;
                } 
            }
        }
        
        public bool IsAccessible {
            // ReSharper disable once SimplifyConditionalTernaryExpression
            get { return this.PrivateKeyInfo == null ? false : this.PrivateKeyInfo.Accessible; }
        }
        public bool? CanExportPrivateKey {
            get {
                var info = this.privKeyInfo;
                if (info == null) {
                    return null;
                }

                try {
                    return this.cert.HasPrivateKey && info.Exportable;
                } catch (CryptographicException) {
                    return null;
                }
            }
        }
        public bool? IsRemovable {
            get {
                try {
                    return this.privKeyInfo == null ? (bool?) null : this.PrivateKeyInfo.Removable;
                } catch (CryptographicException) {
                    return null;
                }
            }
        }
        
        public bool CanDecrypt {
            get {
                return this.PrivateKeyInfo           != null && this.cert.HasPrivateKey &&
                       this.PrivateKeyInfo.KeyNumber == KeyNumber.Exchange;
            }
        }
        
        public bool CanEncrypt {
            get {
                try {
                    return this.PublicKeyInfo != null && this.PublicKeyInfo.KeyNumber == KeyNumber.Exchange;
                }
                catch (CryptographicException) {
                    return false;
                }
            }
        }

        public bool CanSign {
            get {
                return this.PrivateKeyInfo != null && (this.PrivateKeyInfo.KeyNumber == KeyNumber.Signature ||
                                                       this.PrivateKeyInfo.KeyNumber == KeyNumber.Exchange);
            }
        }

        public bool IsReadyForDecrypt {
            get { return this.CanDecrypt && this.PrivateKeyInfo != null && this.PrivateKeyInfo.Accessible; }
        }
        
        public bool IsReadyForEncrypt {
            get { return this.CanEncrypt && this.PublicKeyInfo != null && this.PublicKeyInfo.Accessible; }
        }
        
        public bool IsReadyForSign {
            get { return this.CanSign && this.PublicKeyInfo != null && this.PublicKeyInfo.Accessible; }
        }

        public X509Certificate2 Certificate {
            get { return this.cert;  }
        }
        
        // TODO: https://www.pkisolutions.com/blog/accessing-and-using-certificate-private-keys-in-net-framework-net-core/
        private static CspKeyContainerInfo GetPrivateKeyContainerInfoFromCert(X509Certificate2 cert) {
            // Important: Try to avoid accessing cert.PrivateKey to retrieve cspInfo if possible!
            // Accessing cert.PrivateKey requests access to the private key itself, asking the user for its pin!
            try {
                var cspParams = NativeCapi.GetParameters(cert);
                return cspParams == null ? null : new CspKeyContainerInfo(cspParams);
            } catch (DllNotFoundException) {
                // this is likely to cause a pin prompt!
                var cspAlgorithm = cert.PrivateKey as ICspAsymmetricAlgorithm;
                return cspAlgorithm == null ? null : cspAlgorithm.CspKeyContainerInfo;
            }
        }

        // TODO: https://www.pkisolutions.com/blog/accessing-and-using-certificate-private-keys-in-net-framework-net-core/
        private static CspKeyContainerInfo GetPublicKeyContainerInfoFromCert(X509Certificate2 cert) {
            try {
                var pubKeyAlgorithm = cert.PublicKey.Key as ICspAsymmetricAlgorithm;
                return pubKeyAlgorithm != null ? pubKeyAlgorithm.CspKeyContainerInfo : null;
            }
            catch (CryptographicException) {
                return null;
            }
        }
    }
}