using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace EpiSource.KeePass.Ekf.Util {
    public sealed class MarshaledStructureHandleCollection : IDisposable {
        
        private List<KeyValuePair<Type, IntPtr>> marshaledStructures = new List<KeyValuePair<Type, IntPtr>>();

        public void AddStructure<T>(IntPtr marshaledStructure) {
            if (this.marshaledStructures == null) {
                throw new ObjectDisposedException(typeof(MarshaledStructureHandleCollection).Name);
            }
            this.marshaledStructures.Add(new KeyValuePair<Type, IntPtr>(typeof(T), marshaledStructure));
        }


        public void Dispose() {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing) {
            if (this.marshaledStructures == null) {
                return;
            }

            foreach (var item in this.marshaledStructures) {
                Marshal.DestroyStructure(item.Value, item.Key);
            }

            this.marshaledStructures.Clear();
            this.marshaledStructures = null;
        }
        
        ~MarshaledStructureHandleCollection() {
            this.Dispose(false);
        }
    }
}