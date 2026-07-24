using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static class X509CertificateExtensions {
        public static X509SubjectKeyIdentifierExtension GetSubjectKeyIdentifierExtension(this X509Certificate2 cert) {
            return cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
        }
        
        public static X509KeyUsageFlags GetKeyUsageExtension(this X509Certificate2 cert) {
            return cert.Extensions
                       .OfType<X509KeyUsageExtension>()
                       .Select(usage => usage.KeyUsages)
                       .DefaultIfEmpty(~X509KeyUsageFlags.None)
                       .FirstOrDefault();
        }

        public static bool AllowsKeyUsageAnyOf(this X509Certificate2 cert, params X509KeyUsageFlags[] anyWanted) {
            var allowedFlags = cert.GetKeyUsageExtension();
            return anyWanted.Any(flag => allowedFlags.HasFlag(flag));
        }
        
        public static bool AllowsKeyUsageAllOf(this X509Certificate2 cert, params X509KeyUsageFlags[] allWanted) {
            var allowedFlags = cert.GetKeyUsageExtension();
            return allWanted.All(flag => allowedFlags.HasFlag(flag));
        }
    }
}