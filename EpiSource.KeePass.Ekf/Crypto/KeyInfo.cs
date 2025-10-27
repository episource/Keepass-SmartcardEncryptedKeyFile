namespace EpiSource.KeePass.Ekf.Crypto {
    public sealed class KeyInfo {

        private readonly bool canDecrypt;
        private readonly bool canExport;
        private readonly bool canSign;
        private readonly bool isHardware;
        private readonly bool isRemovable;

        public KeyInfo() : this(false, false, false, false, false) {
            
        }

        public KeyInfo(bool canDecrypt, bool canExport, bool canSign, bool isHardware, bool isRemovable) {
            this.canDecrypt = canDecrypt;
            this.canExport = canExport;
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

        public bool CanSign {
            get {
                return this.canSign;
            }
        }

        public bool IsHardware {
            get {
                return this.isHardware;
            }
        }

        public bool IsRemovable {
            get {
                return this.isRemovable;
            }
        }
    }
}