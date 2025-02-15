using System;
using System.Runtime.InteropServices;

using EpiSource.KeePass.Ekf.Util.Exceptions;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
        private static CryptMsgHandle DecodeEnvelopedCmsImpl(byte[] encodedEnvelopedCms) {
            if (encodedEnvelopedCms == null) {
                throw new ArgumentNullException("encodedEnvelopedCms");
            }

            var msgHandle = PinvokeUtil.DoPinvokeWithException(
                () => NativeCryptMsgPinvoke.CryptMsgOpenToDecode(
                    CryptMsgEncodingTypeFlags.X509_ASN_ENCODING | CryptMsgEncodingTypeFlags.PKCS_7_ASN_ENCODING,
                    CryptMsgFlags.None, CryptMsgType.RetrieveTypeFromHeader,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero),
                r => r.Result != null && !r.Result.IsInvalid);

            PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgUpdate(msgHandle, encodedEnvelopedCms,
                (uint) encodedEnvelopedCms.Length, true));

            uint msgTypeRaw = 0;
            int msgTypeSize = Marshal.SizeOf<uint>();
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgGetParamDword(msgHandle, CryptMsgParamType.CMSG_TYPE_PARAM, 0, ref msgTypeRaw,
                    ref msgTypeSize));
            if (msgTypeRaw != (uint) CryptMsgType.CMSG_ENVELOPED) {
                throw new ArgumentException("No valid enveloped cms message.", "encodedEnvelopedCms");
            }

            return msgHandle;
        }

        private static PortableProtectedBinary GetCryptMsgContent(CryptMsgHandle msgHandle) {
            byte[] content = null;
            int contentSize = 0;
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0,
                    content, ref contentSize));
            
            content = new byte[contentSize];
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(msgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0,
                    content, ref contentSize));

            if (content.Length != contentSize) {
                Array.Clear(content, 0, content.Length);
                throw new Exception("failed to decrypt message.");
            }
            
            return PortableProtectedBinary.Move(content);
        }

        private static PortableProtectedBinary DecryptCryptMsg(CryptMsgHandle msgHandle, NcryptOrContextHandle nCryptKey, int recipientIndex) {
            var para = new CmsgCtrlDecryptPara(nCryptKey, recipientIndex);
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgControl(
                    msgHandle, CryptMsgControlFlags.None, CryptMsgControlType.CMSG_CTRL_DECRYPT, ref para),
                r => CryptoExceptionFactory.forErrorCode(r.Win32ErrorCode));

            return GetCryptMsgContent(msgHandle);
        }
    }
}