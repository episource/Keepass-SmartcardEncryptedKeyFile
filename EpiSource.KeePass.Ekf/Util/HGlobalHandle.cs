using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Util {
    public class HGlobalHandle : SafeHandleZeroOrMinusOneIsInvalid {

        private readonly int size;
        public HGlobalHandle() : base(true) { }
        public HGlobalHandle(bool ownsHandle) : base(true) { }

        public HGlobalHandle(int size) : base(true) {
            this.size = size;
            this.SetHandle(Marshal.AllocHGlobal(size));
        }
            
        public int Size { get { return this.size;  } }

        protected override bool ReleaseHandle() {
            Marshal.FreeHGlobal(this.handle);
            return true;
        }
    }
}