using System;

namespace EpiSource.KeePass.Ekf.Crypto {
    
    [Serializable]
    public sealed class KeyInfo {
        
        private readonly bool canDecrypt;
        private readonly bool canExport;
        private readonly bool canKeyAgree;
        private readonly bool canSign;
        private readonly bool? isHardware;
        private readonly bool? isRemovable;

        public KeyInfo() : this(false, false, false, false, null, null) {
            
        }

        public KeyInfo(bool canDecrypt, bool canExport, bool canKeyAgree, bool canSign, bool? isHardware, bool? isRemovable) {
            this.canDecrypt = canDecrypt;
            this.canExport = canExport;
            this.canKeyAgree = canKeyAgree;
            this.canSign = canSign;
            this.isHardware = isHardware;
            this.isRemovable = isRemovable;
        }
        
        public bool CanDecrypt {
            get {
                return this.canDecrypt;
            }
        }

        public bool CanExport {
            get {
                return this.canExport;
            }
        }

        public bool CanKeyAgree {
            get {
                return this.canKeyAgree;
            }
        }

        public bool CanSign {
            get {
                return this.canSign;
            }
        }

        public bool? IsHardware {
            get {
                return this.isHardware;
            }
        }

        public bool? IsRemovable {
            get {
                return this.isRemovable;
            }
        }
        
        private bool Equals(KeyInfo other) {
            return this.canDecrypt == other.canDecrypt && this.canExport == other.canExport && this.canKeyAgree == other.canKeyAgree && this.canSign == other.canSign && this.isHardware == other.isHardware && this.isRemovable == other.isRemovable;
        }
        public override bool Equals(object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is KeyInfo && this.Equals((KeyInfo) obj);
        }
        public override int GetHashCode() {
            unchecked {
                var hashCode = this.canDecrypt.GetHashCode();
                hashCode = (hashCode * 397) ^ this.canExport.GetHashCode();
                hashCode = (hashCode * 397) ^ this.canKeyAgree.GetHashCode();
                hashCode = (hashCode * 397) ^ this.canSign.GetHashCode();
                hashCode = (hashCode * 397) ^ this.isHardware.GetHashCode();
                hashCode = (hashCode * 397) ^ this.isRemovable.GetHashCode();
                return hashCode;
            }
        }
        
    }
}