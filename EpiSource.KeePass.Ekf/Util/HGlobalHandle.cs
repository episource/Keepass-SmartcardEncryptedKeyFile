using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms.VisualStyles;

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
        
        public HGlobalHandle(IEnumerable<byte> data) 
            : this((data as byte[]) ?? data.ToArray()) {
        }

        public HGlobalHandle(byte[] data) : this(data.Length) {
            Marshal.Copy(data, 0, this.handle, data.Length);
        }
            
        public int Size { get { return this.size;  } }

        public byte[] Read() {
            var data = new byte[this.size];
            Marshal.Copy(this.handle, data, 0, data.Length);
            return data;
        }

        public void ReadTo(IList<byte> to, int offset=0, int count=-1) {
            if (offset >= to.Count) {
                throw new IndexOutOfRangeException("offset");
            }
            count = count == -1 ? to.Count - offset : count;
            if (offset + count > to.Count) {
                throw new ArgumentOutOfRangeException("to");
            }

            if (to is byte[]) {
                Marshal.Copy(this.handle, (byte[]) to, offset, count);
            } else {
                for (var i = 0; i < count; i++) {
                    to[i+offset] = Marshal.ReadByte(this.handle, i);
                }
            }
        }

        protected override bool ReleaseHandle() {
            Marshal.FreeHGlobal(this.handle);
            this.SetHandleAsInvalid();
            return true;
        }
    }
}