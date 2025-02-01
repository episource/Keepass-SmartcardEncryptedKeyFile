using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Windows.Forms;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
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
    }
}