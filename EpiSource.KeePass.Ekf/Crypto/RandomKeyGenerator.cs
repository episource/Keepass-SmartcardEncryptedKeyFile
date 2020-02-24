using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

using KeePassLib.Cryptography;
using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.Crypto {
    public class RandomKeyGenerator {
        public ProtectedBinary Shuffle(string entropy) {
            return this.Shuffle(Encoding.ASCII.GetBytes(entropy));
        }
        
        public ProtectedBinary Shuffle(IEnumerable<byte> entropy) {
            using (var ms = new MemoryStream())
            using (var msWriter = new BinaryWriter(ms)) {
                foreach (var b in entropy) msWriter.Write(b);
                msWriter.Write(Stopwatch.GetTimestamp());
                msWriter.Write(CryptoRandom.Instance.GetRandomBytes(32));

                return new ProtectedBinary(true, CryptoUtil.HashSha256(ms.ToArray()));
            }
        }
    }
}