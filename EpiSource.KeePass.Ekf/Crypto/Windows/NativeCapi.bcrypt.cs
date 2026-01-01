using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.KeePass.Ekf.Util.Windows;

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {

        public const int AesGcmNonceSize = 12;
        private static readonly IReadOnlyDictionary<string, CngInterfaceIdentifier> AvailableCngAlgorithms = EnumerateCngAlgorithms();
        
        
        private static void EncryptOrDecryptAesGcm(PortableProtectedBinary input, out PortableProtectedBinary output, PortableProtectedBinary key, IList<byte> nonce, IList<byte> tag, bool decrypt) {
            if (key.Length != 16 && key.Length != 32) {
                throw new ArgumentOutOfRangeException("key.Length", key.Length, "key must be 128 or 256 bytes.");
            }
            if (nonce.Count != AesGcmNonceSize && (!decrypt || nonce.Count != key.Length)) {
                // 96bits is recommended size (various sources)
                // for some windows builds, BCryptEncrypt fails with STATUS_INVALID_PARAMETER if nonce size differs (own observation)
                // most windows builds support IV with size equal to the key as well (own observation)
                // => for best compatibility limit encryption to fixed IV size of 96bits,
                //    however allow attempt to decrypt longer IV as well
                throw new ArgumentOutOfRangeException("nonce.Count", nonce.Count, "for encryption, 12 bytes / 96bits is the only supported nonce size");
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
                NativeBCryptPinvoke.BCryptGetPropertyKeyLengthStruct(
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
                                ? NativeBCryptPinvoke.BCryptDecryptAuthenticatedCipher(keyHandle, inputHandle, inputHandle.Size, ref cryptoData, nonceHandle, nonceHandle.Size, outputHandle, outputHandle.Size, out ignored)
                                : NativeBCryptPinvoke.BCryptEncryptAuthenticatedCipher(keyHandle, inputHandle, inputHandle.Size, ref cryptoData, nonceHandle, nonceHandle.Size, outputHandle, outputHandle.Size, out ignored)
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

        private static IReadOnlyDictionary<string, CngInterfaceIdentifier> EnumerateCngAlgorithms() {
            int numAlgs;
            IntPtr algInfoBufferPtr = IntPtr.Zero;
            NativeBCryptPinvoke.BCryptEnumAlgorithms((BcryptOperations) 0xff, out numAlgs, ref algInfoBufferPtr).EnsureSuccess();

            try {
                var algorithms = new Dictionary<string, CngInterfaceIdentifier>(numAlgs);
                

                for (int i = 0; i < numAlgs; i++) {
                    var algInfoPtr = algInfoBufferPtr + i * Marshal.SizeOf<BcryptAlgorithmIdentifier>();
                    var algInfo = Marshal.PtrToStructure<BcryptAlgorithmIdentifier>(algInfoPtr);
                    algorithms.Add(algInfo.pszName, algInfo.dwClass);
                }
                
                return new ReadOnlyDictionary<string, CngInterfaceIdentifier>(algorithms);
            } finally {
                NativeBCryptPinvoke.BCryptFreeBuffer(algInfoBufferPtr);
            }
        }
        
        private static BcryptPublicKey ImportPublicKey(X509Certificate2 cert) {
            BCryptKeyHandle keyHandle;
            if (!NativeCryptPinvoke.CryptImportPublicKeyInfoEx2(
                CryptEncodingTypeFlags.X509_ASN_ENCODING | CryptEncodingTypeFlags.PKCS_7_ASN_ENCODING,
                new CryptPublicKeyInfoHandle(cert), CryptFindOIDInfoKeyTypeFlag.CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, IntPtr.Zero, out keyHandle)) {
                return new BcryptPublicKey();
            }

            const string propAlgorithmName = "AlgorithmName";
            
            var cngAlgNameBuffer = Array.Empty<byte>();
            int cngAlgNameSize;
            if (NTStatusUtil.NTStatus.STATUS_BUFFER_TOO_SMALL != NativeBCryptPinvoke.BCryptGetPropertyBinary(
                keyHandle, propAlgorithmName, cngAlgNameBuffer, cngAlgNameBuffer.Length, out cngAlgNameSize, 0)) {
                return new BcryptPublicKey() {KeyHandle =  keyHandle, CngAlgorithmName = ""};
            }
            
            cngAlgNameBuffer = new byte[cngAlgNameSize];

            NativeBCryptPinvoke.BCryptGetPropertyBinary(
                    keyHandle, propAlgorithmName, cngAlgNameBuffer, cngAlgNameBuffer.Length, out cngAlgNameSize, 0)
                            .EnsureSuccess();
            
            var cngAlgorithmName = Encoding.Unicode.GetString(cngAlgNameBuffer, 0, Math.Max(0, cngAlgNameSize - 2));
            return new BcryptPublicKey() {KeyHandle =  keyHandle, CngAlgorithmName = cngAlgorithmName};
        }
    }
}