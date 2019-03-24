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
        private CspKeyContainerInfo keyInfo;

        private CspKeyContainerInfo KeyInfo {
            get { return this.keyInfo ?? (this.keyInfo = GetKeyContainerInfoFromCert(this.cert)); }
        }
        
        private RSACryptoServiceProviderKeyPair(X509Certificate2 cert, CspKeyContainerInfo keyInfo) {
            this.cert = cert;
            this.keyInfo = keyInfo;
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

            var cspInfo = GetKeyContainerInfoFromCert(cert);
            if (cspInfo != null || permitLazyCspInfo) {
                return new RSACryptoServiceProviderKeyPair(cert, cspInfo);
            } 
            
            if (nullOnError) {
                return null;
            }
            throw new ArgumentException("Certificate not backed by windows crypto service provider.",
                "cert"); 
        }

        public bool? IsSmartcard {
            get { return this.KeyInfo == null ? (bool?)null : this.KeyInfo.HardwareDevice; }
        }
        
        public bool IsSmartcardAvailable {
            // ReSharper disable once SimplifyConditionalTernaryExpression
            get { return this.KeyInfo == null ? false : this.keyInfo.Accessible; }
        }
        public bool? CanExportPrivateKey {
            get {
                var info = this.keyInfo;
                if (info == null) {
                    return null;
                }
                
                return this.cert.HasPrivateKey && info.Exportable;
            }
        }
        public bool? IsRemovable {
            get { return this.keyInfo == null ? (bool?)null : this.KeyInfo.Removable; }
        }
        public bool CanSign {
            get {
                return this.KeyInfo != null && (this.KeyInfo.KeyNumber == KeyNumber.Signature ||
                                                this.KeyInfo.KeyNumber == KeyNumber.Exchange);
            }
        }

        public bool CanEncrypt {
            get {
                try {
                    // ReSharper disable once ConditionIsAlwaysTrueOrFalse
                    return this.KeyInfo           != null && this.cert.PublicKey != null &&
                           this.KeyInfo.KeyNumber == KeyNumber.Exchange;
                }
                catch (CryptographicException) {
                    return false;
                }
            }
        }

        public bool CanDecrypt {
            get {
                return this.KeyInfo != null && this.cert.HasPrivateKey && this.KeyInfo.KeyNumber == KeyNumber.Exchange;
            }
        }
        public X509Certificate2 Certificate {
            get { return this.cert;  }
        }
        
        [OnDeserialized]
        private void OnDeserializedSetKeyInfo(StreamingContext context) {
            this.keyInfo = GetKeyContainerInfoFromCert(this.Certificate);
        }

        private static CspKeyContainerInfo GetKeyContainerInfoFromCert(X509Certificate2 cert) {
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
    }
}