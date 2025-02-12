using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Windows.Forms;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
        public sealed class ComparableIssuerSerial {
            
            private string issuerName;
            private string serialNumber;

            public ComparableIssuerSerial(X509Certificate2 certificate) {
                this.issuerName = certificate.IssuerName.Name;
                this.serialNumber = certificate.SerialNumber;
            }
            
            public ComparableIssuerSerial(X509IssuerSerial issuerSerial) {
                this.issuerName = issuerSerial.IssuerName;
                this.serialNumber = issuerSerial.SerialNumber;
            }

            public string IssuerName {
                get { return this.issuerName; }
            }
        
            public string SerialNumber {
                get { return this.SerialNumber; }
            }

            private bool Equals(ComparableIssuerSerial other) {
                return this.issuerName == other.issuerName && this.serialNumber == other.serialNumber;
            }
            public override bool Equals(object obj) {
                if (ReferenceEquals(null, obj)) return false;
                if (ReferenceEquals(this, obj)) return true;
                return obj is ComparableIssuerSerial && this.Equals((ComparableIssuerSerial) obj);
            }
            public override int GetHashCode() {
                unchecked {
                    return ((this.issuerName != null ? this.issuerName.GetHashCode() : 0) * 397) ^ (this.serialNumber != null ? this.serialNumber.GetHashCode() : 0);
                }
            }
        }

        public sealed class AesGcmCryptoCipherResult {
            private IList<byte> ciphertext;
            private IList<byte> nonce;
            private IList<byte> tag;

            internal AesGcmCryptoCipherResult(IList<byte> ciphertext, IList<byte> nonce, IList<byte> tag, bool copyTagAndText) {
                if (copyTagAndText) {
                    ciphertext = ciphertext.ToList();
                    tag = tag.ToList();
                }
                nonce = nonce.ToList();
                
                this.ciphertext = new ReadOnlyCollection<byte>(ciphertext);
                this.nonce = new ReadOnlyCollection<byte>(nonce);
                this.tag = new ReadOnlyCollection<byte>(tag);
            }
            
            public AesGcmCryptoCipherResult(IList<byte> ciphertext, IList<byte> nonce, IList<byte> tag) : this(ciphertext, nonce, tag, true) {}
            
            public IList<byte> Ciphertext { get { return this.ciphertext; } }
            public IList<byte> Nonce { get { return this.nonce; } }
            public IList<byte> Tag { get { return this.tag; } }
        }
    }
}