using System.IO;

using KeePassLib.Utility;

namespace EpiSource.Unblocker.Util {
    
    public static class StreamExtensions {
        public static byte[] ReadAllBinaryAndClose(this Stream stream) {
            try {
                using (var buffer = new MemoryStream()) {
                    MemUtil.CopyStream(stream, buffer);
                    return buffer.ToArray();
                }
            } finally {
                stream.Close();
            }
        }
    }
    
}