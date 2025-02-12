using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Util {
    [Serializable]
    public sealed class PortableProtectedBinary : ISerializable {

        /// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protectedmemory.protect
        private const int BlockSize = 16;

        private const MemoryProtectionScope DefaultProtectionScope = MemoryProtectionScope.SameProcess;
        private const MemoryProtectionScope PortableProtectionScope = MemoryProtectionScope.SameLogon;

        private readonly byte[] protectedData;
        private readonly int plainLength;

        private PortableProtectedBinary(byte[] protectedData, int plainLength) {
            this.protectedData = protectedData;
            this.plainLength = plainLength;
        }
        
        private PortableProtectedBinary(SerializationInfo info, StreamingContext context) {
            this.plainLength = info.GetInt32("plainLength");
            this.protectedData = (byte[])info.GetValue("portableData", typeof(byte[]));
            
            ProtectedMemory.Unprotect(this.protectedData, PortableProtectionScope);
            ProtectedMemory.Protect(this.protectedData, DefaultProtectionScope);
        }
        
        public void GetObjectData(SerializationInfo info, StreamingContext context) {
            var portableData = new byte[this.protectedData.Length];
            Array.Copy(this.protectedData, portableData, portableData.Length);
            
            ProtectedMemory.Unprotect(portableData, DefaultProtectionScope);
            ProtectedMemory.Protect(portableData, PortableProtectionScope);
            
            info.AddValue("portableData", portableData);
            info.AddValue("plainLength", this.plainLength);
        }

        public static PortableProtectedBinary CopyOf(IList<byte> data) {
            var numBlocks = data.Count / BlockSize;
            if (numBlocks * BlockSize < data.Count) numBlocks++;
            
            var protectedData = new byte[numBlocks * BlockSize];
            data.CopyTo(protectedData, 0);
            ProtectedMemory.Protect(protectedData, DefaultProtectionScope);
            
            return new PortableProtectedBinary(protectedData, data.Count);
        }
        
        public static PortableProtectedBinary Move(byte[] data) {
            try {
                return CopyOf(data);
            } finally {
                Array.Clear(data, 0, data.Length);
            }
        }
        
        public static PortableProtectedBinary Move(IList<byte> data) {
            if (data.IsReadOnly) throw new ArgumentException("data is read-only");
            
            try {
                return CopyOf(data);
            } finally {
                data.Clear();
            }
        }
        
        public int Length {
            get { return this.plainLength; }
        }

        public PortableProtectedBinary Clone() {
            var clonedData = new byte[this.protectedData.Length];
            Array.Copy(this.protectedData, clonedData, this.protectedData.Length);
            
            return new PortableProtectedBinary(clonedData, this.plainLength);
        }

        public byte[] ReadUnprotected() {
            var protectedDataCopy = new byte[this.protectedData.Length];
            Array.Copy(this.protectedData, protectedDataCopy, this.protectedData.Length);
            ProtectedMemory.Unprotect(protectedDataCopy, DefaultProtectionScope);

            if (protectedDataCopy.Length == this.plainLength) {
                return protectedDataCopy;
            }

            var result = new byte[this.plainLength];
            Array.Copy(protectedDataCopy, 0, result, 0, this.plainLength);
            Array.Clear(protectedDataCopy, 0, protectedDataCopy.Length);
            return result;
        }

        private bool Equals(PortableProtectedBinary other) {
            if (this.plainLength != other.plainLength) {
                return false;
            }
            if ((this.protectedData == null) != (other.protectedData == null)) {
                return false;
            }
            if (this.protectedData == null) {
                return true;
            }
            return this.protectedData.SequenceEqual(other.protectedData);
        }
        public override bool Equals(object obj) {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj is PortableProtectedBinary && this.Equals((PortableProtectedBinary) obj);
        }
        public override int GetHashCode() {
            unchecked {
                return ((this.protectedData != null ? this.protectedData.GetHashCode() : 0) * 397) ^ this.plainLength;
            }
        }
    }
}