using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static class X509CertificateExtensions {
        public static X509SubjectKeyIdentifierExtension GetSubjectKeyIdentifierExtension(this X509Certificate2 cert) {
            return cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
        }
    }
}