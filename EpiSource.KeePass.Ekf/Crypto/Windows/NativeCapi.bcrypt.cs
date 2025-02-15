using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public static partial class NativeCapi {
        private static void EncryptOrDecryptAesGcm(PortableProtectedBinary input, out PortableProtectedBinary output, PortableProtectedBinary key, IList<byte> nonce, IList<byte> tag, bool decrypt) {
            if (key.Length != 16 && key.Length != 32) {
                throw new ArgumentOutOfRangeException("key.Length", key.Length, "key must be 128 or 256 bytes.");
            }
            if (nonce.Count != key.Length) {
                throw new ArgumentOutOfRangeException("nonce.Length", nonce.Count, "nonce must be of same length as key");
            }
            if (input.Length % key.Length != 0) {
                throw new ArgumentOutOfRangeException("data.Length", input.Length, "data size must be multiple of key size");
            }
            
            BCryptAlgorithmHandle cryptoAlgorithm;
            var lastResult = NativeBCryptPinvoke.BCryptOpenAlgorithmProvider(out cryptoAlgorithm, "AES");
            using (cryptoAlgorithm) {
                lastResult.EnsureSuccess();

                var chainingMode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                NativeBCryptPinvoke.BCryptSetProperty(cryptoAlgorithm, "ChainingMode", chainingMode, chainingMode.Length).EnsureSuccess();

                BcryptKeyLengthsStruct tagSizeInfo;
                int ignored;
                NativeBCryptPinvoke.BCryptGetProperty(
                    cryptoAlgorithm, "AuthTagLength", out tagSizeInfo,
                    Marshal.SizeOf<BcryptKeyLengthsStruct>(), out ignored).EnsureSuccess();

                if (tag.Count < tagSizeInfo.dwMinLength || tag.Count > tagSizeInfo.dwMaxLength
                        || (tag.Count - tagSizeInfo.dwMinLength) % tagSizeInfo.dwIncrement != 0) {
                    throw new ArgumentOutOfRangeException("tag.length", tag.Count, "Unsupported tag size. Tag size must be within " + tagSizeInfo.dwMinLength + ".." + tagSizeInfo.dwMaxLength + " with increment " + tagSizeInfo.dwIncrement + ".");
                }

                BCryptKeyHandle keyHandle;
                using (var keyDataHandle = new PortableProtectedBinaryHandle(key)) {
                    lastResult = NativeBCryptPinvoke.BCryptGenerateSymmetricKey(cryptoAlgorithm, out keyHandle, IntPtr.Zero, 0, keyDataHandle, keyDataHandle.Size);
                }
                lastResult.EnsureSuccess();

                using (keyHandle) 
                using (var inputHandle = new PortableProtectedBinaryHandle(input))
                using (var outputHandle = new PortableProtectedBinaryHandle(input.Length))
                using (var nonceHandle = new HGlobalHandle(nonce))
                using (var tagHandle = new HGlobalHandle((int)tag.Count)) {
                    if (decrypt) {
                        Marshal.Copy((tag as byte[]) ?? tag.ToArray(), 0, tagHandle.DangerousGetHandle(), tag.Count);
                    }

                    var cryptoData = new BcryptAuthenticatedCipherModeInfo() {
                        cbSize = Marshal.SizeOf<BcryptAuthenticatedCipherModeInfo>(),
                        dwInfoVersion = 1,
                        pbNonce = nonceHandle.DangerousGetHandle(),
                        cbNonce = nonce.Count,
                        pbAuthData = IntPtr.Zero,
                        cbAuthData = 0,
                        pbTag = tagHandle.DangerousGetHandle(),
                        cbTag = tagHandle.Size,
                        pbMacContext = IntPtr.Zero,
                        cbMacContext = 0,
                        cbAAD = 0,
                        cbData = 0,
                        dwFlags = 0
                    };

                    try {
                        (decrypt
                                ? NativeBCryptPinvoke.BCryptDecrypt(keyHandle, inputHandle, inputHandle.Size, ref cryptoData, nonceHandle, nonceHandle.Size, outputHandle, outputHandle.Size, out ignored)
                                : NativeBCryptPinvoke.BCryptEncrypt(keyHandle, inputHandle, inputHandle.Size, ref cryptoData, nonceHandle, nonceHandle.Size, outputHandle, outputHandle.Size, out ignored)
                            ).EnsureSuccess();
                        output = outputHandle.ReadProtected();

                        if (!decrypt) {
                            tagHandle.ReadTo(tag);
                        }
                    } catch (Win32Exception e) {
                        if (unchecked((NTStatusUtil.NTStatus) e.NativeErrorCode) == NTStatusUtil.NTStatus.STATUS_AUTH_TAG_MISMATCH) {
                            throw new MessageAuthenticationCodeMismatchException(e.Message, e, e.HResult);
                        }
                        throw new CryptographicException("AES-GCM encryption/decryption failed: " + e.Message, e);
                    }
                }
            }
        }
    }
}