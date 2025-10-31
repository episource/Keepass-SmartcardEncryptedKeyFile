using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;
using EpiSource.KeePass.Ekf.Crypto.Windows.Exceptions;
using EpiSource.KeePass.Ekf.Util;

using KeePassLib.Cryptography;

using Microsoft.Win32.SafeHandles;

// ReSharper disable InconsistentNaming
// ReSharper disable EnumUnderlyingTypeIsInt

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
        private static readonly Func<PinvokeUtil.PinvokeResult<bool>, bool> isSuccessOrMissingKeyPredicate = r =>
            r.Result || r.Win32ErrorCode == unchecked((int) CryptoResult.NTE_BAD_KEYSET)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.SCARD_E_NO_SMARTCARD)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.SCARD_E_NO_READERS_AVAILABLE);

        public static bool IsCancelledByUserException(CryptographicException ex) {
            return ex is CryptoOperationCancelledException || unchecked((CryptoResult)ex.HResult) == CryptoResult.SCARD_W_CANCELLED_BY_USER;
        }
        
        /// <summary>
        /// Silently checks if private key is accessible. The alternatives implemented in .Net framework may show UI to ask for missing Smart Card etc.
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        public static bool IsCertificatePrivateKeyAccessible(X509Certificate2 cert) {
            var optOwner = IntPtr.Zero;
            var keyHandleRaw = IntPtr.Zero;
            var keySpec = CryptPrivateKeySpec.UNDEFINED;
            var mustFreeHandle = false;

            var directAcquireResult = PinvokeUtil.DoPinvokeWithException(() => NativeCertPinvoke.CryptAcquireCertificatePrivateKey(cert.Handle,
                    CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG,
                    ref optOwner, out keyHandleRaw, out keySpec, out mustFreeHandle),
                isSuccessOrMissingKeyPredicate);

            using (NcryptOrContextHandle.of(keyHandleRaw, mustFreeHandle, keySpec)) {
                return directAcquireResult;
            }
        }

        public static bool IsInputRequiredException(CryptographicException ex) {
            return ex is InputRequiredException || unchecked((CryptoResult)ex.HResult) == CryptoResult.NTE_SILENT_CONTEXT;
        }

        public static bool IsWrongPinException(CryptographicException ex) {
            return ex is WrongPinException || unchecked((CryptoResult) ex.HResult) == CryptoResult.SCARD_W_WRONG_CHV;
        }

        public static bool IsPinBlockedException(CryptographicException ex) {
            return ex is PinBlockedException || unchecked((CryptoResult) ex.HResult) == CryptoResult.SCARD_W_CHV_BLOCKED;
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
                if (unchecked((CryptoResult)errorCode) == CryptoResult.CRYPT_E_NOT_FOUND) {
                    return null;
                }

                throw new CryptographicException(errorCode);
            };

            var pcbData = 0;
            var success = NativeCertPinvoke.CertGetCertificateContextProperty(cert.Handle,
                CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                IntPtr.Zero, ref pcbData);
            if (!success) {
                return onFailure();
            }

            var pvData = Marshal.AllocHGlobal(pcbData);
            try {
                success = NativeCertPinvoke.CertGetCertificateContextProperty(cert.Handle,
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

        public static PortableProtectedBinary DecryptEnvelopedCms(byte[] encodedEnvelopedCms, bool alwaysSilent=false, string contextDescription=null, IntPtr uiOwner=new IntPtr(), PortableProtectedString pin=null) {
            if (encodedEnvelopedCms == null) {
                throw new ArgumentNullException("encodedEnvelopedCms");
            }

            var envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(encodedEnvelopedCms);

            var certMap = GetAvailableCertificates(envelopedCms.Certificates);

            var recipientIndex = -1;
            var exceptions = new List<Exception>();
            foreach (var recipient in envelopedCms.RecipientInfos) {
                recipientIndex++;

                if (!(recipient.RecipientIdentifier.Value is X509IssuerSerial) || recipient.Type != RecipientInfoType.KeyTransport) {
                    continue;
                }

                List<X509Certificate2> matchingCerts;
                var identifier = (X509IssuerSerial) recipient.RecipientIdentifier.Value;
                if (!certMap.TryGetValue(new ComparableIssuerSerial(identifier), out matchingCerts)) {
                    continue;
                }

                foreach (var recipientCert in matchingCerts.Where(recipientCert => recipientCert.HasPrivateKey)) {
                    try {
                        var cspParams = NativeCapi.GetParameters(recipientCert);
                        var cspInfo = new CspKeyContainerInfo(cspParams);
                        if (cspInfo.KeyNumber != KeyNumber.Exchange || !cspInfo.Accessible) {
                            continue;
                        }

                        return DecryptEnvelopedCms(envelopedCms, encodedEnvelopedCms, recipientCert, recipientIndex, alwaysSilent, contextDescription, uiOwner, pin);
                    } catch (Exception ex) {
                        exceptions.Add(ex);
                        // continue trying next one
                    }
                }
            }

            if (exceptions.Count == 0) {
                throw new CryptographicException("No available key found for any recipient of enveloped-data message.");
            }
            throw new CryptographicException("No available key found for any recipient of enveloped-data message.", new AggregateException("Decryption failed.", exceptions));
        }

        public static PortableProtectedBinary DecryptEnvelopedCms(byte[] encodedEnvelopedCms, IKeyPair recipient, bool alwaysSilent=false, string contextDescription=null, IntPtr uiOwner=new IntPtr(), PortableProtectedString pin=null) {
            if (recipient == null) {
                throw new ArgumentNullException("recipient");
            }
            return DecryptEnvelopedCms(encodedEnvelopedCms, recipient.Certificate, alwaysSilent, contextDescription, uiOwner, pin);
        }

        public static PortableProtectedBinary DecryptEnvelopedCms(byte[] encodedEnvelopedCms, X509Certificate2 recipientCert, bool alwaysSilent=false, string contextDescription=null, IntPtr uiOwner=new IntPtr(), PortableProtectedString pin=null) {
            if (encodedEnvelopedCms == null) {
                throw new ArgumentNullException("encodedEnvelopedCms");
            }
            if (recipientCert == null) {
                throw new ArgumentNullException("recipientCert");
            }
            
            var envelopedCms = new EnvelopedCms();
            envelopedCms.Decode(encodedEnvelopedCms);
            
            int recipientIndex;
            RecipientInfo recipientInfo;
            
            if (!FindRecipient(envelopedCms, recipientCert, out recipientIndex, out recipientInfo)) {
                throw new ArgumentException("Recipient not authorized or invalid.", "recipient");
            }
            if (recipientInfo.Type != RecipientInfoType.KeyTransport) {
                throw new ArgumentException("Recipient type is not KeyTransport.", "recipient");
            }
            
            return DecryptEnvelopedCms(envelopedCms, encodedEnvelopedCms, recipientCert, recipientIndex, alwaysSilent, contextDescription, uiOwner, pin);
        }

        public static PortableProtectedBinary DecryptAesGcm(AesGcmCryptoCipherResult cipherResult, PortableProtectedBinary key) {
            PortableProtectedBinary plaintext;
            EncryptOrDecryptAesGcm(PortableProtectedBinary.CopyOf(cipherResult.Ciphertext), out plaintext, key, cipherResult.Nonce, cipherResult.Tag, true);
            return plaintext;
        }
        
        public static PortableProtectedBinary DecryptAesGcm(IList<byte> ciphertext, PortableProtectedBinary key, IList<byte> nonce, IList<byte> tag) {
            return DecryptAesGcm(PortableProtectedBinary.CopyOf(ciphertext), key, nonce, tag);
        }
        
        public static PortableProtectedBinary DecryptAesGcm(PortableProtectedBinary ciphertext, PortableProtectedBinary key, IList<byte> nonce, IList<byte> tag) {
            PortableProtectedBinary plaintext;
            EncryptOrDecryptAesGcm(ciphertext, out plaintext, key, nonce, tag, true);
            return plaintext;
        }

        public static AesGcmCryptoCipherResult EncryptAesGcm(PortableProtectedBinary plaintext, PortableProtectedBinary key, byte[] nonce=null, int tagSizeBytes=16) {
            if (nonce == null) {
                nonce = CryptoRandom.Instance.GetRandomBytes(AesGcmNonceSize);
            }
            
            PortableProtectedBinary ciphertext;
            var tag = new byte[tagSizeBytes];
            
            EncryptOrDecryptAesGcm(plaintext, out ciphertext, key, nonce, tag, false);
            return new AesGcmCryptoCipherResult(ciphertext.ReadUnprotected(), nonce, tag);
        }
        
        public static KeyInfo QueryCertificatePrivateKey(X509Certificate cert) {
            // see also:
            //  - https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
            //  - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgetprovparam
            
            var cspParams = NativeCapi.GetParameters(cert);
            if (cspParams == null) {
                return new KeyInfo();
            }
            
            
            bool isHardware = false;
            bool isRemovable = false;
            bool canExport = false;
            
            // 0: Ncrypt Key Provider (no indication) - let's assume CanDecrypt for now
            // 1: We can decrypt, the key is of type Exchange
            bool canDecrypt = cspParams.KeyNumber == 0 || cspParams.KeyNumber == (int)KeyNumber.Exchange;
            bool canSign = canDecrypt || cspParams.KeyNumber == (int)KeyNumber.Signature;


            NcryptOrContextHandle providerHandle = null;
            
            // CryptNG
            if (cspParams.KeyNumber == 0) {
                NCryptContextHandle ncryptProviderHandle = null;
                DoNcryptWithException(() => NativeNCryptPinvoke.NCryptOpenStorageProvider(out ncryptProviderHandle, cspParams.ProviderName, 0));
                providerHandle = ncryptProviderHandle;
            } else {
                CryptContextHandle cspHandle = null;
                NativeLegacyCapiPinvoke.CryptAcquireContext(out cspHandle, null, cspParams.ProviderName, cspParams.ProviderType, CryptAcquireContextFlags.CRYPT_SILENT | CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT);
                providerHandle = cspHandle;
            }

            using (providerHandle) {
                byte[] providerImplementation = getNcryptOrCspProperty(providerHandle, "Impl Type", CryptGetProvParamType.PP_IMPTYPE, true);
                isHardware = providerImplementation.Length > 0 && (providerImplementation[0] & 0x1) == 0x1;
                isRemovable = providerImplementation.Length > 0 && (providerImplementation[0] & 0x8) == 0x8;
                canExport = !isHardware;
            }
            
            
            var optOwner = IntPtr.Zero;
            var keyHandleRaw = IntPtr.Zero;
            var keySpec = CryptPrivateKeySpec.UNDEFINED;
            var mustFreeHandle = false;

            PinvokeUtil.DoPinvokeWithException(() => NativeCertPinvoke.CryptAcquireCertificatePrivateKey(cert.Handle,
                    CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                    // attempt to access cached key information if smart card is not connected!
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_USE_PROV_INFO_FLAG
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG,
                    ref optOwner, out keyHandleRaw, out keySpec, out mustFreeHandle),
                isSuccessOrMissingKeyPredicate);

            using (NcryptOrContextHandle keyHandle = NcryptOrContextHandle.of(keyHandleRaw, mustFreeHandle, keySpec)) {
                if (keyHandle.IsInvalid) {
                    return new KeyInfo(canDecrypt, canExport, canSign, isHardware, isRemovable);
                }
                
                byte[] keyImplementation = getNcryptOrCspProperty(keyHandle, "Impl Type", CryptGetProvParamType.PP_IMPTYPE, true);
                if (keyImplementation.Length > 0) {
                    isHardware = keyImplementation.Length > 0 && (keyImplementation[0] & 0x1) == 0x1;
                    isRemovable = keyImplementation.Length > 0 && (keyImplementation[0] & 0x8) == 0x8;
                    canExport = !isHardware;
                }

                var ncryptKeyHandle = keyHandle as NCryptContextHandle;
                if (ncryptKeyHandle != null) {
                    byte[] exportPolicy = GetNcryptProperty(ncryptKeyHandle, "Export Policy", NCryptGetPropertyFlags.NCRYPT_SILENT_FLAG);
                    canExport = exportPolicy.Length == 0 ? canExport : (exportPolicy[0] & 0x1) == 0x1; 
                    
                    byte[] keyUsagePolicy = GetNcryptProperty(ncryptKeyHandle, "Key Usage", NCryptGetPropertyFlags.NCRYPT_SILENT_FLAG);
                    canDecrypt = keyUsagePolicy.Length == 0 ? canDecrypt : (keyUsagePolicy[0] & 0x1) == 0x1;
                    canSign = keyUsagePolicy.Length    == 0 ? canSign : (keyUsagePolicy[0]    & 0x2) == 0x2;
                }
            }
            
            return new KeyInfo(canDecrypt, canExport, canSign, isHardware, isRemovable);
        }

        private static PortableProtectedBinary DecryptEnvelopedCms(
                EnvelopedCms envelopedCms, byte[] encodedEnvelopedCms, X509Certificate2 recipientCert, int recipientIndex, bool alwaysSilent,
                string optContextDescription, IntPtr optOwner, PortableProtectedString optPin
        ) {
            if (envelopedCms == null) {
                throw new ArgumentNullException("envelopedCms");
            }
            if (recipientCert == null) {
                throw new ArgumentNullException("recipientCert");
            }
        
            var silent = alwaysSilent || optPin != null;
            var keyHandleRaw = IntPtr.Zero;
            var keySpec = CryptPrivateKeySpec.UNDEFINED;
            var mustFreeHandle = false;
            PinvokeUtil.DoPinvokeWithException(() => NativeCertPinvoke.CryptAcquireCertificatePrivateKey(recipientCert.Handle,
                CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
                | (optOwner != IntPtr.Zero && ! silent ? CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG : 0) 
                | (silent ? CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG : 0), 
                ref optOwner, out keyHandleRaw, out keySpec, out mustFreeHandle));
 
            using (var keyHandle = NcryptOrContextHandle.of(keyHandleRaw, mustFreeHandle, keySpec))
            using (var msgHandle = DecodeEnvelopedCmsImpl(encodedEnvelopedCms)) 
            {
                if (optPin != null) setNcryptOrCspPropertyUA(
                    keyHandle, "SmartCardPin",
                    keyHandle.KeySpec == CryptPrivateKeySpec.AT_KEYEXCHANGE ? CryptSetProvParamType.PP_KEYEXCHANGE_PIN : CryptSetProvParamType.PP_SIGNATURE_PIN,
                    silent, optPin);

                if (optContextDescription != null) SetNcryptOrCspPropertyU(keyHandle, "Use Context", CryptSetProvParamType.PP_PIN_PROMPT_STRING, silent, optContextDescription);
                
                return DecryptCryptMsg(msgHandle, keyHandle, recipientIndex);
            }
        }
        
        private static bool FindRecipient(EnvelopedCms envelopedCms, X509Certificate2 recipientCert, out int recipientIndex,
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
                                            r.Item3.IssuerName   == recipientCert.IssuerName.Name &&
                                            r.Item3.SerialNumber == recipientCert.SerialNumber);
            recipientIndex = recipient.Item1;
            recipientInfo = recipient.Item2;
            return recipientIndex >= 0;
        }
        
        private static Dictionary<ComparableIssuerSerial, List<X509Certificate2>> GetAvailableCertificates(X509Certificate2Collection additionalCerts) {
            using (var userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine)) {
                userStore.Open(OpenFlags.ReadOnly);
                machineStore.Open(OpenFlags.ReadOnly);
                
                var userStoreCerts = userStore.Certificates.Cast<X509Certificate2>();
                var machineStoreCerts = machineStore.Certificates.Cast<X509Certificate2>();

                return additionalCerts.Cast<X509Certificate2>().Concat(userStoreCerts).Concat(machineStoreCerts)
                                      .GroupBy(c => new ComparableIssuerSerial(c))
                                      .ToDictionary(g => g.Key, g => g.ToList());
            }
        }

        private static void SetNcryptOrCspPropertyU(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam,  bool silent, string value) {
            setNcryptOrCspProperty(handle, ncryptProperty, cspParam, silent, Encoding.Unicode.GetBytes(value + "\0"));
        }
        
        private static void setNcryptOrCspPropertyUA(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam,  bool silent, PortableProtectedString value) {
            var valueBytes = handle is NCryptContextHandle ? value.ReadUnprotectedUtf16NullTerminated() : value.ReadUnprotectedAsciiNullTerminated();
            
            try {
                setNcryptOrCspProperty(handle, ncryptProperty, cspParam, silent, valueBytes);
            } finally {
                Array.Clear(valueBytes, 0, valueBytes.Length);
            }
        }
        
        private static void setNcryptOrCspProperty(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam, bool silent, byte[] value) {
            if (handle is NCryptContextHandle) {
                SetNcryptProperty((NCryptContextHandle)handle, ncryptProperty, value, silent ? NCryptSetPropertyFlags.NCRYPT_SILENT_FLAG : NCryptSetPropertyFlags.None);
            } else {
                SetCspProperty((CryptContextHandle)handle, cspParam, value);
            }
        }

        private static byte[] getNcryptOrCspProperty(NcryptOrContextHandle handle, string ncryptProperty, CryptGetProvParamType cspParam, bool silent) {
            if (handle is NCryptContextHandle) {
                return GetNcryptProperty((NCryptContextHandle)handle, ncryptProperty, silent ? NCryptGetPropertyFlags.NCRYPT_SILENT_FLAG : NCryptGetPropertyFlags.None);
            } else {
                return GetCspProperty((CryptContextHandle)handle, cspParam);
            }
        }

    }
}