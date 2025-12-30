using System;

namespace EpiSource.KeePass.Ekf.Crypto {
    
    [Serializable]
    public sealed class KeyInfo {

        private readonly bool canKeyAgree;
        private readonly bool canKeyTransfer;
        private readonly bool canSign;
        private readonly bool canExport;
        private readonly bool? isHardware;
        private readonly bool? isRemovable;

        public KeyInfo() : this(false, false, false, false, null, null) {
            
        }

        public KeyInfo(bool canKeyAgree, bool canKeyTransfer, bool canSign, bool canExport, bool? isHardware, bool? isRemovable) {
            this.canKeyTransfer = canKeyTransfer;
            this.canKeyAgree = canKeyAgree;
            this.canSign = canSign;
            this.isHardware = isHardware;
            this.isRemovable = isRemovable;
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
        
        public bool CanKeyTransfer {
            get {
                return this.canKeyTransfer;
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
            return this.canKeyAgree == other.canKeyAgree && this.canKeyTransfer == other.canKeyTransfer && this.canExport == other.canExport && this.canSign == other.canSign && this.isHardware == other.isHardware && this.isRemovable == other.isRemovable;
        }
        public override bool Equals(object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is KeyInfo && this.Equals((KeyInfo) obj);
        }
        public override int GetHashCode() {
            unchecked {
                var hashCode = this.canKeyAgree.GetHashCode();
                hashCode = (hashCode * 397) ^ this.canKeyTransfer.GetHashCode();
                hashCode = (hashCode * 397) ^ this.canExport.GetHashCode();
                hashCode = (hashCode * 397) ^ this.canSign.GetHashCode();
                hashCode = (hashCode * 397) ^ this.isHardware.GetHashCode();
                hashCode = (hashCode * 397) ^ this.isRemovable.GetHashCode();
                return hashCode;
            }
        }
        
    }
}