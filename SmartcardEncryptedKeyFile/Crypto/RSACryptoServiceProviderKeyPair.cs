using System;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Episource.KeePass.EKF.Crypto.Windows;

namespace Episource.KeePass.EKF.Crypto {
    /// <summary>
    /// Gives access to RSA smart cards that are compatible with the windows crypto service provider framework.
    /// </summary>
    [Serializable]
    public class RSACryptoServiceProviderKeyPair : IKeyPair {

        private readonly X509Certificate2 cert;
        
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

            var isRsa = cert.PublicKey.Key is RSA;
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
            get { return this.PrivateKeyInfo == null ? (bool?)null : this.PrivateKeyInfo.HardwareDevice; }
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
                
                return this.cert.HasPrivateKey && info.Exportable;
            }
        }
        public bool? IsRemovable {
            get { return this.privKeyInfo == null ? (bool?)null : this.PrivateKeyInfo.Removable; }
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
        
        [OnDeserialized]
        private void OnDeserializedSetKeyInfo(StreamingContext context) {
            this.privKeyInfo = GetPrivateKeyContainerInfoFromCert(this.Certificate);
        }
        
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