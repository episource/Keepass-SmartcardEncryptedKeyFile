using System;
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
        
        private RSACryptoServiceProviderKeyPair(X509Certificate2 cert, CspKeyContainerInfo keyInfo) {
            this.cert = cert;
            this.keyInfo = keyInfo;
        }

        public static RSACryptoServiceProviderKeyPair FromX509Certificate(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, false);  
        }
        
        public static RSACryptoServiceProviderKeyPair FromX509CertificateOrNull(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, true);
        }

        private static RSACryptoServiceProviderKeyPair FromX509CertificateInternal(X509Certificate2 cert,
            bool nullOnError) {
            
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
            if (cspInfo != null) {
                return new RSACryptoServiceProviderKeyPair(cert, cspInfo);
            }
            if (nullOnError) {
                return null;
            }
            throw new ArgumentException("Certificate not backed by windows crypto service provider.",
                "cert"); 
        }

        public bool IsSmartcard {
            get { return this.keyInfo.HardwareDevice; }
        }
        
        public bool IsSmartcardAvailable {
            get { return this.keyInfo.Accessible; }
        }
        public bool CanExportPrivateKey {
            get { return this.cert.HasPrivateKey && this.keyInfo.Exportable; }
        }
        public bool IsRemovable {
            get { return this.keyInfo.Removable; }
        }
        public bool CanSign {
            get { return this.keyInfo.KeyNumber == KeyNumber.Signature || this.keyInfo.KeyNumber == KeyNumber.Exchange; }
        }

        public bool CanEncrypt {
            get {
                try {
                    // ReSharper disable once ConditionIsAlwaysTrueOrFalse
                    return this.cert.PublicKey != null && this.keyInfo.KeyNumber == KeyNumber.Exchange;
                }
                catch (CryptographicException) {
                    return false;
                }
            }
        }

        public bool CanDecrypt {
            get { return this.cert.HasPrivateKey && this.keyInfo.KeyNumber == KeyNumber.Exchange; }
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