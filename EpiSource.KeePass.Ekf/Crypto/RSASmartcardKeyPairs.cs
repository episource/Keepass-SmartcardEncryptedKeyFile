using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace EpiSource.KeePass.Ekf.Crypto {
    // ReSharper disable once InconsistentNaming
    public static class RSASmartcardKeyPairs {       
        /// <summary>
        /// Gets all encryption key pairs backed by smartcards implementing the PIV (personal identity verification)
        /// standard. Basic support for these smartcards is provided by windows without additional drivers.
        /// </summary>
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        /// <returns>
        /// A list of piv smartcard backed rsa key pairs suitable for key exchange / encryption.
        /// </returns>
        public static IList<IKeyPair> GetAllPivKeyPairs() {
            using (var userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine)) {
                userStore.Open(OpenFlags.ReadOnly);
                machineStore.Open(OpenFlags.ReadOnly);
                
                var userStoreCerts = userStore.Certificates.Cast<X509Certificate2>();
                var machineStoreCerts = machineStore.Certificates.Cast<X509Certificate2>();

                var certs =
                    userStoreCerts.Union(machineStoreCerts)
                                  .GroupBy(c => c.Thumbprint)
                                  .Select(cGroup =>
                                      (IKeyPair) RSACryptoServiceProviderKeyPair.FromX509CertificateOrNull(
                                          cGroup.First()));
                
                // blocks if busy hardware devices are involved
                return ListEncryptionCardsAsList(certs);
            }
        }

        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        public static IList<IKeyPair> GetAllKeyPairs() {
            return GetAllPivKeyPairs();
        }

        private static IList<IKeyPair> ListEncryptionCardsAsList(IEnumerable<IKeyPair> unfilteredKeyPairs) {
            return unfilteredKeyPairs
                   .Where(c => c != null && c.IsSmartcard.GetValueOrDefault(false) && c.CanEncrypt && c.CanDecrypt)
                   .ToList().AsReadOnly();
        }
    }
}