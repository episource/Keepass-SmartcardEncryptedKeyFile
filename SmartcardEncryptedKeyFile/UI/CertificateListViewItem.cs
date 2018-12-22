using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;

namespace Episource.KeePass.EKF.UI {
    public class CertificateListViewItem {
        private ListViewItem boundItem = null;

        public CertificateListViewItem(X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException(paramName: "cert");
            }

            if (!cert.HasPrivateKey) {
                throw new ArgumentException(paramName: "cert", message: "Certificate without private key.");
            }
            
            if (!(cert.PrivateKey is RSA)) {
                throw new ArgumentException(paramName: "cert", message: "Not an RSA certificate.");
            }

            this.certificate = cert;
        }

        private readonly X509Certificate2 certificate;
        private readonly PublicKey publicKey;

        public X509Certificate2 Certificate {
            get { return this.certificate; }
        }

        public PublicKey PublicKey {
            get { return this.publicKey; }
        }

        public void AddToList(ListView listView) {
            if (this.boundItem != null && this.boundItem.ListView == listView) {
                return;
            }

            if (this.boundItem != null) {
                throw new InvalidOperationException("Already bound to another list view instance.");
            }
            
            this.boundItem = new ListViewItem(text: "-");
            this.boundItem.Tag = this;
            this.boundItem.SubItems.Add(this.Certificate.Thumbprint);
        }
    }
}