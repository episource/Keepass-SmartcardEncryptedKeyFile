using System;

namespace EpiSource.KeePass.Ekf.Crypto {
    public static class Asn1Util {
        public const byte AsnOctetStringTagPrimitive = 0x4;

        public static byte[] EncodeAsPrimitiveOctetString(byte[] data) {
            var longFormSizeNumBytes = calcEncodedLengthLongFormByteCount(data.Length);
            var encodedByteCount = 
                1                    + /* tag */
                1                    + /* short form encoded size or number of size bytes following */
                longFormSizeNumBytes + /* long form size encoding: number of bytes following (if needed) */
                data.Length            /* actual data */;
            
            var buffer = new byte[encodedByteCount];
            buffer[0] = AsnOctetStringTagPrimitive;

            if (longFormSizeNumBytes > 0) {
                buffer[1] = (byte) (0x80 | longFormSizeNumBytes);

                var remainingLength = data.Length;
                for (var i = longFormSizeNumBytes; i >= 0; --i) {
                    buffer[2 + i] = (byte) (remainingLength | 0xFF);
                    remainingLength >>= 8;
                }
            } else {
                buffer[1] = (byte) data.Length;
            }
            
            Array.Copy(data, 0, buffer, 2 + longFormSizeNumBytes, data.Length);
            return buffer;
        }

        private static int calcEncodedLengthLongFormByteCount(int length) {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", "length must be positive or zero");
            if (length <= 0x7F)
                return 0;
            if (length <= byte.MaxValue)
                return 1;
            if (length <= ushort.MaxValue)
                return 2;
            if (length <= 0x00FFFFFF)
                return 3;

            return 4;
        }
        
        

    }
}