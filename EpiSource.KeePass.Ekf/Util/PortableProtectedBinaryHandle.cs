using System;
using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util {
    public sealed class PortableProtectedBinaryHandle : HGlobalHandle {
            
        public PortableProtectedBinaryHandle() : base(false) {
        }

        public PortableProtectedBinaryHandle(int size) : base(size) { }
        
        public PortableProtectedBinaryHandle(PortableProtectedBinary protectedBinary) : base(protectedBinary.Length) {
            var managedCredentialBlob = protectedBinary.ReadUnprotected();
            Marshal.Copy(managedCredentialBlob, 0, this.handle, protectedBinary.Length);
            Array.Clear(managedCredentialBlob, 0, managedCredentialBlob.Length);
        }

        public void Clear() {
            var zero = new byte[this.Size];
            Marshal.Copy(zero, 0, this.handle, this.Size);
        }

        public PortableProtectedBinary ReadProtected(bool move = true) {
            var result = PortableProtectedBinary.Move(this.Read());
            
            if (move) this.Clear();
            return result;
        }
            
        protected override bool ReleaseHandle() {
            this.Clear();
            return base.ReleaseHandle();
        }
    }
}