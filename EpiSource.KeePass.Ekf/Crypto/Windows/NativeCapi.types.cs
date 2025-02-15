using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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
        
        /// <summary>
        /// Set of relevant error codes.
        /// Reference: winerror.h, ntstatus.h
        /// </summary>
        internal enum CryptoResult : uint {
            ERROR_SUCCESS =                 0x00,
            ERROR_MORE_DATA =               0xEA,
            
            NTE_BAD_UID =                   0x80090001,
            NTE_BAD_HASH =                  0x80090002,
            NTE_BAD_KEY =                   0x80090003,
            NTE_BAD_LEN =                   0x80090004,
            NTE_BAD_DATA =                  0x80090005,
            NTE_BAD_SIGNATURE =             0x80090006,
            NTE_BAD_VER =                   0x80090007,
            NTE_BAD_ALGID =                 0x80090008,
            NTE_BAD_FLAGS =                 0x80090009,
            NTE_BAD_TYPE =                  0x8009000A,
            NTE_BAD_KEY_STATE =             0x8009000B,
            NTE_BAD_HASH_STATE =            0x8009000C,
            NTE_NO_KEY =                    0x8009000D,
            NTE_NO_MEMORY =                 0x8009000E,
            NTE_EXISTS =                    0x8009000F,
            NTE_PERM =                      0x80090010,
            NTE_NOT_FOUND =                 0x80090011,
            NTE_DOUBLE_ENCRYPT =            0x80090012,
            NTE_BAD_PROVIDER =              0x80090013,
            NTE_BAD_PROV_TYPE =             0x80090014,
            NTE_BAD_PUBLIC_KEY =            0x80090015,
            NTE_BAD_KEYSET =                0x80090016,
            NTE_PROV_TYPE_NOT_DEF =         0x80090017,
            NTE_PROV_TYPE_ENTRY_BAD =       0x80090018,
            NTE_KEYSET_NOT_DEF =            0x80090019,
            NTE_KEYSET_ENTRY_BAD =          0x8009001A,
            NTE_PROV_TYPE_NO_MATCH =        0x8009001B,
            NTE_SIGNATURE_FILE_BAD =        0x8009001C,
            NTE_PROVIDER_DLL_FAIL =         0x8009001D,
            NTE_PROV_DLL_NOT_FOUND =        0x8009001E,
            NTE_BAD_KEYSET_PARAM =          0x8009001F,
            NTE_FAIL =                      0x80090020,
            NTE_SYS_ERR =                   0x80090021,
            NTE_BUFFER_TOO_SMALL =          0x80090028,
            NTE_NOT_SUPPORTED =             0x80090029,
            NTE_NO_MORE_ITEMS =             0x8009002a,
            NTE_SILENT_CONTEXT =            0x80090022,
            NTE_TOKEN_KEYSET_STORAGE_FULL = 0x80090023,
            NTE_TEMPORARY_PROFILE =         0x80090024,
            NTE_FIXEDPARAMETER =            0x80090025,
            NTE_INVALID_HANDLE =            0x80090026,
            NTE_INVALID_PARAMETER =         0x80090027,
            NTE_BUFFERS_OVERLAP =           0x8009002B,
            NTE_DECRYPTION_FAILURE =        0x8009002C,
            NTE_INTERNAL_ERROR =            0x8009002D,
            NTE_UI_REQUIRED =               0x8009002E,
            NTE_HMAC_NOT_SUPPORTED =        0x8009002F,
            NTE_DEVICE_NOT_READY =          0x80090030,
            NTE_AUTHENTICATION_IGNORED =    0x80090031,
            NTE_VALIDATION_FAILED =         0x80090032,
            NTE_INCORRECT_PASSWORD =        0x80090033,
            NTE_ENCRYPTION_FAILURE =        0x80090034,
            NTE_DEVICE_NOT_FOUND =          0x80090035,
            CRYPT_E_NOT_FOUND =             0x80092004,
            
            /// wrong pin
            SCARD_W_WRONG_CHV =             0x8010006B,
            SCARD_W_CHV_BLOCKED =           0x8010006C,
            SCARD_W_CANCELLED_BY_USER =     0x8010006E,
        }
    }
}