using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;

namespace EpiSource.KeePass.Ekf.UI {
    public class CertificateListViewItem {
        private ListViewItem boundItem;

        public CertificateListViewItem(X509Certificate2 cert) {
            if (cert == null) {
                throw new ArgumentNullException("cert");
            }

            if (!cert.HasPrivateKey) {
                throw new ArgumentException("Certificate without private key.", "cert");
            }
            
            if (!(cert.PrivateKey is RSA)) {
                throw new ArgumentException("Not an RSA certificate.", "cert");
            }

            this.certificate = cert;
        }

        private readonly X509Certificate2 certificate;

        public X509Certificate2 Certificate {
            get { return this.certificate; }
        }

        public PublicKey PublicKey {
            get { return this.Certificate.PublicKey; }
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