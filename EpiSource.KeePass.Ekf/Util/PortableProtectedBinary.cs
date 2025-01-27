using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Cryptography;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
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

        public static PortableProtectedBinary CopyOf(byte[] data) {
            var numBlocks = data.Length / BlockSize;
            if (numBlocks * BlockSize < data.Length) numBlocks++;
            
            var protectedData = new byte[numBlocks * BlockSize];
            Array.Copy(data, 0, protectedData, 0, data.Length);
            ProtectedMemory.Protect(protectedData, DefaultProtectionScope);
            
            return new PortableProtectedBinary(protectedData, data.Length);
        }
        
        public static PortableProtectedBinary Move(byte[] data) {
            try {
                return CopyOf(data);
            } finally {
                Array.Clear(data, 0, data.Length);
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
    }
}