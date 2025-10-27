using System;

using EpiSource.KeePass.Ekf.Util;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        private static byte[] GetCspProperty(CryptContextHandle cspHandle, CryptGetProvParamType dwParam) {
            var valueSize = 0;
            // https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
            var result = PinvokeUtil.DoPinvokeDetailedWithException(() => NativeLegacyCapiPinvoke.CryptGetProvParam(cspHandle, dwParam, null, ref valueSize, 0),
                res => res.Result || res.Win32ErrorCode == (int) CryptoResult.ERROR_MORE_DATA || res.Win32ErrorCode == (int) CryptoResult.ERROR_INVALID_PARAMETER);

            if (result.Win32ErrorCode == (int)CryptoResult.ERROR_INVALID_PARAMETER) {
                return Array.Empty<byte>();
            }
                
            var value = new byte[valueSize];
            PinvokeUtil.DoPinvokeWithException(() => NativeLegacyCapiPinvoke.CryptGetProvParam(cspHandle, dwParam, value, ref valueSize, 0));

            Array.Resize(ref value, valueSize);
            return value;
        }

        private static void SetCspProperty(CryptContextHandle cspHandle, CryptSetProvParamType dwParam, byte[] value) {
            PinvokeUtil.DoPinvokeWithException(() => NativeLegacyCapiPinvoke.CryptSetProvParam(
                cspHandle == null ? new CryptContextHandle(IntPtr.Zero, false, CryptPrivateKeySpec.UNDEFINED) : cspHandle, dwParam, value, 0));
        }
    }
}