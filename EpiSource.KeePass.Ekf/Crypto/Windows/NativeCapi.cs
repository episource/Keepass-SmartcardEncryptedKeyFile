using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.UI.Windows;
using EpiSource.KeePass.Ekf.Util;

using KeePassLib;
using KeePassLib.Security;

// ReSharper disable InconsistentNaming
// ReSharper disable EnumUnderlyingTypeIsInt

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {

        public static bool IsCancelledByUserException(CryptographicException ex) {
            return ex.HResult == (int)CapiErrorCodes.SCARD_W_CANCELLED_BY_USER;
        }
        
        /// <summary>
        /// Returns the CspParameters of a certificate with MS-CAPI backed private key.
        /// </summary>
        /// <param name="cert">The certificate to query.</param>
        /// <returns>The private key parameters if there is a private key, otherwise <code>null</code></returns>
        /// <exception cref="CryptographicException">Querying the private key parameters failed unexpectedly.</exception>
        public static CspParameters GetParameters(X509Certificate cert) {
            Func<CspParameters> onFailure = () => {
                var errorCode = Marshal.GetLastWin32Error();
                if (errorCode == (int) CapiErrorCodes.CRYPT_E_NOT_FOUND) {
                    return null;
                }

                throw new CryptographicException(errorCode);
            };

            var pcbData = 0;
            var success = NativeCapiPinvoke.CertGetCertificateContextProperty(cert.Handle,
                CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                IntPtr.Zero, ref pcbData);
            if (!success) {
                return onFailure();
            }

            var pvData = Marshal.AllocHGlobal(pcbData);
            try {
                success = NativeCapiPinvoke.CertGetCertificateContextProperty(cert.Handle,
                    CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    pvData, ref pcbData);

                if (!success) {
                    return onFailure();
                }
                
                var nativeKeyInfo = Marshal.PtrToStructure<CryptKeyProvInfo>(pvData);
                
                // Let's ignore ParentWindowHandle & KeyPassword for now
                var cspParams = new CspParameters {
                    KeyContainerName = nativeKeyInfo.pwszContainerName,
                    ProviderName = nativeKeyInfo.pwszProvName,
                    ProviderType = (int) nativeKeyInfo.dwProvType,
                    KeyNumber = (int) nativeKeyInfo.dwKeySpec,
                    Flags = CspProviderFlags.NoFlags
                };

                cspParams.Flags |=
                    ((KeyProvInfoFlags) nativeKeyInfo.dwFlags & KeyProvInfoFlags.CRYPT_MACHINE_KEYSET) ==
                    KeyProvInfoFlags.CRYPT_MACHINE_KEYSET
                        ? CspProviderFlags.UseMachineKeyStore
                        : CspProviderFlags.NoFlags;
                cspParams.Flags |=
                    ((KeyProvInfoFlags) nativeKeyInfo.dwFlags & KeyProvInfoFlags.CRYPT_SILENT) ==
                    KeyProvInfoFlags.CRYPT_SILENT
                        ? CspProviderFlags.NoPrompt
                        : CspProviderFlags.NoFlags;

                return cspParams;
            }
            finally {
                Marshal.FreeHGlobal(pvData);
            }
        }

        public static byte[] DecryptEnvelopedCms(byte[] encodedEnvelopedCms, IKeyPair recipient, string optPinUsage, IntPtr optOwner,  ProtectedString optPin) {
            if (encodedEnvelopedCms == null) {
                throw new ArgumentNullException("encodedEnvelopedCms");
            }

            var envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(encodedEnvelopedCms);
            
            int recipientIndex;
            RecipientInfo recipientInfo;
            
            if (!FindRecipient(envelopedCms, recipient, out recipientIndex, out recipientInfo)) {
                throw new ArgumentException("Recipient not authorized or invalid.", "recipient");
            }
            if (recipientInfo.Type != RecipientInfoType.KeyTransport) {
                throw new ArgumentException("Recipient type is not KeyTransport.", "recipient");
            }

           
            var silent = optPin != null;
            var keyHandleRaw = IntPtr.Zero;
            var keySpec = CryptPrivateKeySpec.UNDEFINED;
            var mustFreeHandle = false;
            PinvokeUtil.DoPinvokeWithException(() => NativeCapiPinvoke.CryptAcquireCertificatePrivateKey(recipient.Certificate.Handle,
                CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
                | (optOwner != IntPtr.Zero ? CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG : 0) 
                | (silent ? CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG : 0), 
                ref optOwner, out keyHandleRaw, out keySpec, out mustFreeHandle));
 
            using (var keyHandle = NcryptOrContextHandle.of(keyHandleRaw, mustFreeHandle, keySpec))
            using (var msgHandle = DecodeEnvelopedCmsImpl(encodedEnvelopedCms)) 
            {
                if (optPin != null) setNcryptOrCspPropertyUA(
                    keyHandle, "SmartCardPin",
                    keyHandle.KeySpec == CryptPrivateKeySpec.AT_KEYEXCHANGE ? CryptSetProvParamType.PP_KEYEXCHANGE_PIN : CryptSetProvParamType.PP_SIGNATURE_PIN,
                    silent, optPin);

                if (optPinUsage != null) SetNcryptOrCspPropertyU(keyHandle, "Use Context", CryptSetProvParamType.PP_PIN_PROMPT_STRING, silent, optPinUsage);
                
                return DecryptCryptMsg(msgHandle, keyHandle, recipientIndex);
            }
        }
        
        internal static bool FindRecipient(EnvelopedCms envelopedCms, IKeyPair recipientKeyPair, out int recipientIndex,
            out RecipientInfo recipientInfo) {
            var recipient = envelopedCms.RecipientInfos
                                        .OfType<RecipientInfo>()
                                        .Select((r, i) => new Tuple<int, RecipientInfo>(i, r))
                                        .Where(r => r.Item2.RecipientIdentifier.Value is X509IssuerSerial)
                                        .Select((r, i) =>
                                            new Tuple<int, RecipientInfo, X509IssuerSerial>(
                                                r.Item1, r.Item2, (X509IssuerSerial) r.Item2.RecipientIdentifier.Value))
                                        .DefaultIfEmpty(
                                            new Tuple<int, RecipientInfo, X509IssuerSerial>(-1, null,
                                                default(X509IssuerSerial)))
                                        .First(r =>
                                            r.Item3.IssuerName   == recipientKeyPair.Certificate.IssuerName.Name &&
                                            r.Item3.SerialNumber == recipientKeyPair.Certificate.SerialNumber);
            recipientIndex = recipient.Item1;
            recipientInfo = recipient.Item2;
            return recipientIndex >= 0;
        }

        private static void SetNcryptOrCspPropertyU(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam,  bool silent, string value) {
            setNcryptOrCspProperty(handle, ncryptProperty, cspParam, silent, Encoding.Unicode.GetBytes(value + "\0"));
        }
        
        private static void setNcryptOrCspPropertyUA(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam,  bool silent, ProtectedString value) {
            var valueBytes = handle is NCryptContextHandle ? value.ReadUnicodeNullTerminated() : value.ReadAsciiNullTerminated();
            
            try {
                setNcryptOrCspProperty(handle, ncryptProperty, cspParam, silent, valueBytes);
            } finally {
                Array.Clear(valueBytes, 0, valueBytes.Length);
            }
        }
        
        private static void setNcryptOrCspProperty(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam,  bool silent, byte[] value) {
            if (handle is NCryptContextHandle) {
                SetNcryptProperty((NCryptContextHandle)handle, ncryptProperty, value, silent ? NCryptSetPropertyFlags.NCRYPT_SILENT_FLAG : NCryptSetPropertyFlags.None);
            } else {
                SetCspProperty((CryptContextHandle)handle, cspParam, value);
            }
        }

        private static byte[] GetCspProperty(CryptContextHandle cspHandle, CryptGetProvParamType dwParam) {
            var valueSize = 0;
            // https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
            PinvokeUtil.DoPinvokeWithException(() => NativeLegacyCapiPinvoke.CryptGetProvParam(cspHandle, dwParam, null, ref valueSize, 0),
                res => res || Marshal.GetLastWin32Error() == (int) CapiErrorCodes.ERROR_MORE_DATA);
                
            var value = new byte[valueSize];
            PinvokeUtil.DoPinvokeWithException(() => NativeLegacyCapiPinvoke.CryptGetProvParam(cspHandle, dwParam, value, ref valueSize, 0));

            Array.Resize(ref value, valueSize);
            return value;
        }

        private static void SetCspProperty(CryptContextHandle cspHandle, CryptSetProvParamType dwParam, byte[] value) {
            PinvokeUtil.DoPinvokeWithException(() => NativeLegacyCapiPinvoke.CryptSetProvParam(
                cspHandle == null ? new CryptContextHandle(IntPtr.Zero, false, CryptPrivateKeySpec.UNDEFINED) : cspHandle, dwParam, value, 0));
        }
         
        /// https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
        private static byte[] GetNcryptProperty(NCryptContextHandle keyHandle, string propertyName) {
            var valueSize = 0;
            DoNcryptWithException(() => NativeNCryptPinvoke.NCryptGetProperty(keyHandle, propertyName, null, 0, out valueSize, NCryptGetPropertyFlags.None));
                
            var value = new byte[valueSize];
            DoNcryptWithException(() => NativeNCryptPinvoke.NCryptGetProperty(keyHandle, propertyName, value, value.Length, out valueSize, NCryptGetPropertyFlags.None));

            Array.Resize(ref value, valueSize);
            return value;
        }
        
        private static void SetNcryptProperty(NCryptContextHandle keyHandle, string propertyName, byte[] value, NCryptSetPropertyFlags flags) {
            var result = NativeNCryptPinvoke.NCryptSetProperty(keyHandle, propertyName, value, value.Length , flags);
            if (result != NcryptResultCode.ERROR_SUCCESS) {
                throw new CryptographicException((int)result);
            }
        }

        private static CryptMsgHandle DecodeEnvelopedCmsImpl(byte[] encodedEnvelopedCms) {
            if (encodedEnvelopedCms == null) {
                throw new ArgumentNullException("encodedEnvelopedCms");
            }

            var msgHandle = PinvokeUtil.DoPinvokeWithException(
                () => NativeCryptMsgPinvoke.CryptMsgOpenToDecode(
                    CryptMsgEncodingTypeFlags.X509_ASN_ENCODING | CryptMsgEncodingTypeFlags.PKCS_7_ASN_ENCODING,
                    CryptMsgFlags.None, CryptMsgType.RetrieveTypeFromHeader,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero),
                r => r != null && !r.IsInvalid);

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

        private static byte[] GetCryptMsgContent(CryptMsgHandle msgHandle) {
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
                throw new Exception("failed to decrypt message.");
            }
            
            return content;
        }

        private static byte[] DecryptCryptMsg(CryptMsgHandle msgHandle, NcryptOrContextHandle nCryptKey, int recipientIndex) {
            var para = new CmsgCtrlDecryptPara(nCryptKey, recipientIndex);
            PinvokeUtil.DoPinvokeWithException(() =>
                NativeCryptMsgPinvoke.CryptMsgControl(
                    msgHandle, CryptMsgControlFlags.None, CryptMsgControlType.CMSG_CTRL_DECRYPT, ref para),
                (int errCode) => {
                    var winEx = new Win32Exception(errCode);
                    return (errCode == (int)CapiErrorCodes.SCARD_W_CANCELLED_BY_USER) ? new OperationCanceledException(winEx.Message, winEx) : (Exception)winEx;
                });

            return GetCryptMsgContent(msgHandle);
        }

        private static NcryptResultCode DoNcryptWithException(Func<NcryptResultCode> ncryptFunction, params NcryptResultCode[] validResults) {
            var internalResult = ncryptFunction();
            if (ncryptFunction() != NcryptResultCode.ERROR_SUCCESS && (validResults == null || !validResults.Contains(internalResult))) {
                throw new CryptographicException((int)internalResult);
            }
            return internalResult;
        }
    }
}