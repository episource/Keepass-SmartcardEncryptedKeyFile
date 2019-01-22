using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Episource.KeePass.EKF.Crypto.Windows;

namespace Episource.KeePass.EKF.Crypto {
    /// <summary>
    /// Gives access to RSA smart cards that are compatible with the windows crypto service provider framework.
    /// </summary>
    public class RSACryptoServiceProviderKeyPair : IKeyPair {

        private readonly X509Certificate2 cert;
        private readonly CspKeyContainerInfo keyInfo;
        
        private RSACryptoServiceProviderKeyPair(X509Certificate2 cert, CspKeyContainerInfo keyInfo) {
            this.cert = cert;
            this.keyInfo = keyInfo;
        }

        public static RSACryptoServiceProviderKeyPair FromX509Certificate(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, nullOnError: false);  
        }
        
        public static RSACryptoServiceProviderKeyPair FromX509CertificateOrNull(X509Certificate2 cert) {
            return FromX509CertificateInternal(cert, nullOnError: true);
        }

        private static RSACryptoServiceProviderKeyPair FromX509CertificateInternal(X509Certificate2 cert,
            bool nullOnError) {
            
            if (cert == null) {
                if (nullOnError) {
                    return null;
                }
                throw new ArgumentNullException(paramName: "cert");
            }

            var isRsa = cert.PublicKey.Key is RSA;
            if (!isRsa) {
                if (nullOnError) {
                    return null;
                }
                throw new ArgumentException(message: "Not an RSA based certificate.", paramName: "cert");
            }


            // Important: Try to avoid accessing cert.PrivateKey to retrieve cspInfo if possible!
            // Accessing cert.PrivateKey requests access to the private key itself, asking the user for its pin!
            try {
                var cspParams = NativeCapi.GetParameters(cert);
                var cspInfo = new CspKeyContainerInfo(cspParams);
                return new RSACryptoServiceProviderKeyPair(cert, cspInfo);
            } catch (DllNotFoundException) {
                // this is likely to cause a pin prompt!
                var cspAlgorithm = cert.PrivateKey as ICspAsymmetricAlgorithm;
                if (cspAlgorithm != null) {
                    return new RSACryptoServiceProviderKeyPair(cert, cspAlgorithm.CspKeyContainerInfo);
                }
                if (nullOnError) {
                    return null;
                }
                
                throw new ArgumentException(message: "Certificate not backed by windows crypto service provider.",
                    paramName: "cert");
            }
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
                    return this.cert.PublicKey != null && this.keyInfo.KeyNumber == KeyNumber.Exchange;
                }
                catch (CryptographicException e) {
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
    }
}