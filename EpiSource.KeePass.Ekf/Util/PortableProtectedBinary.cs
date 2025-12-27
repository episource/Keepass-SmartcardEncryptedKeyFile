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

        public static PortableProtectedBinary CopyOf(IList<byte> data, int offset = 0, int count = -1) {
            if (count < 0) {
                count = data.Count - offset;
            }
            
            var numBlocks = count / BlockSize;
            if (numBlocks * BlockSize < count || numBlocks == 0) numBlocks++;
            
            var protectedData = new byte[numBlocks * BlockSize];
            for (int i = 0; i < count; i++) {
                protectedData[i] = data[i + offset];
            }
            
            ProtectedMemory.Protect(protectedData, DefaultProtectionScope);
            return new PortableProtectedBinary(protectedData, count);
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

        public PortableProtectedBinary CopyRange(int offset = 0, int count = -1) {
            if (count < 0) count = this.Length - offset;

            if (offset == 0 && count == this.Length) {
                return this;
            }
            
            var numBlocks = count / BlockSize;
            if (numBlocks * BlockSize < count) numBlocks++;
            
            var clone = new byte[numBlocks * BlockSize];
            this.ReadUnprotectedTo(clone, offset, 0, count);
            ProtectedMemory.Protect(clone, DefaultProtectionScope);
            
            return new PortableProtectedBinary(clone, count);
        }
        
        public byte[] ReadUnprotected() {
            var unprotected = new byte[this.Length];
            this.ReadUnprotectedTo(unprotected);
            return unprotected;
        }

        public void ReadUnprotectedTo(byte[] target, int offset = 0, int targetOffset = 0, int count = -1) {
            if (offset + count > this.Length) {
                throw new ArgumentException("offset + count > length");
            }
            if (count < 0) {
                count = this.Length - offset;
            }
            
            var protectedDataCopy = new byte[this.protectedData.Length];
            Array.Copy(this.protectedData, protectedDataCopy, this.protectedData.Length);
            ProtectedMemory.Unprotect(protectedDataCopy, DefaultProtectionScope);
            
            Array.Copy(protectedDataCopy, offset, target, targetOffset, count);
            Array.Clear(protectedDataCopy, 0, protectedDataCopy.Length);
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