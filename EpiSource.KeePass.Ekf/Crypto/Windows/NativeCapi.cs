using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;
using EpiSource.KeePass.Ekf.Crypto.Windows.Exceptions;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.KeePass.Ekf.Util.Windows;

using KeePassLib.Cryptography;

// ReSharper disable InconsistentNaming
// ReSharper disable EnumUnderlyingTypeIsInt

namespace EpiSource.KeePass.Ekf.Crypto.Windows {
    public static partial class NativeCapi {
        
        private static readonly Func<PinvokeUtil.PinvokeResult<bool>, bool> isSuccessOrMissingKeyPredicate = r =>
            r.Result || r.Win32ErrorCode == unchecked((int) CryptoResult.NTE_NO_KEY)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.CRYPT_E_NOT_FOUND)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.CRYPT_E_NO_KEY_PROPERTY)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.NTE_BAD_KEY)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.NTE_BAD_KEYSET)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.SCARD_E_NO_SMARTCARD)
                     || r.Win32ErrorCode == unchecked((int) CryptoResult.SCARD_E_NO_READERS_AVAILABLE);

        public static bool IsCancelledByUserException(CryptographicException ex) {
            return ex is CryptoOperationCancelledException || unchecked((CryptoResult)ex.HResult) == CryptoResult.SCARD_W_CANCELLED_BY_USER;
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

            var cryptMsgHandle = DecodeEnvelopedCmsImpl(encodedEnvelopedCms);
            var recipients = GetRecipientsDangerous(cryptMsgHandle);

            var exceptions = new List<Exception>();
            foreach (var recipient in recipients) {
                try {
                    return DecryptEnvelopedCmsImpl(cryptMsgHandle, recipient, alwaysSilent, contextDescription, uiOwner, pin);
                } catch (Exception ex) {
                    exceptions.Add(ex);
                    // continue trying next one
                }
            }

            const string errorMsg = "No available key found for any recipient of enveloped-data message.";
            if (exceptions.Count == 0) {
                throw new CryptographicException(errorMsg);
            }
            if (exceptions.Count == 1) {
                ExceptionDispatchInfo.Capture(exceptions[0]).Throw();
            }
            throw new AggregateException(errorMsg, exceptions);
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
            
            var cryptMsgHandle = DecodeEnvelopedCmsImpl(encodedEnvelopedCms);
            var recipients = GetRecipientsDangerous(cryptMsgHandle, withoutCerts:true)
                             .Where(r => r.RecipientCertId.IsMatchingCert(recipientCert))
                             .Select(r => r.SetRecipientCert(recipientCert));
           
            var exceptions = new List<Exception>();
            foreach (var recipient in recipients) {
                try {
                    return DecryptEnvelopedCmsImpl(cryptMsgHandle, recipient, alwaysSilent, contextDescription, uiOwner, pin);
                } catch (CryptographicException ex) {
                    if (IsInputRequiredException(ex) || IsPinBlockedException(ex) || IsWrongPinException(ex)) {
                        throw;
                    }
                    
                    exceptions.Add(ex);
                    // continue trying next one
                } catch (Exception ex) {
                    exceptions.Add(ex);
                    // continue trying next one
                }
            }
            
            if (exceptions.Count == 0) {
                throw new CryptographicException("Recipient not authorized or invalid.");
            }
            
            if (exceptions.Count == 1) {
                ExceptionDispatchInfo.Capture(exceptions[0]).Throw();
            }
            throw new AggregateException("Decryption failed using given recipient certificate.", exceptions);
        }

        public static byte[] EncryptEnvelopedCms(PortableProtectedBinary plaintextContent, CmsRecipientCollection recipients, string contentEncryptionOid = KnownOids.AlgAesCbc256, string contentTypeOid = KnownOids.GenericCmsData, CryptographicAttributeObjectCollection unprotectedAttributes = null, bool strictRfc5753=true) {
            return EncryptEnvelopedCms(plaintextContent, recipients.Cast<CmsRecipient>().ToList(), contentEncryptionOid, contentTypeOid, unprotectedAttributes, strictRfc5753);
        }
        
        public static byte[] EncryptEnvelopedCms(PortableProtectedBinary plaintextContent, IEnumerable<X509Certificate2> recipients, string contentEncryptionOid = KnownOids.AlgAesCbc256, string contentTypeOid = KnownOids.GenericCmsData, CryptographicAttributeObjectCollection unprotectedAttributes = null, bool strictRfc5753=true) {
            return EncryptEnvelopedCms(plaintextContent, recipients.Select(c => new CmsRecipient(SubjectIdentifierType.SubjectKeyIdentifier, c)).ToList(), contentEncryptionOid, contentTypeOid, unprotectedAttributes, strictRfc5753);
        }

        public static byte[] EncryptEnvelopedCms(PortableProtectedBinary plaintextContent, IEnumerable<CmsRecipient> recipients, string contentEncryptionOid=KnownOids.AlgAesCbc256, string contentTypeOid=KnownOids.GenericCmsData, CryptographicAttributeObjectCollection unprotectedAttributes=null, bool strictRfc5753=true) {
            var recipientsCollection = recipients as IReadOnlyCollection<CmsRecipient> ?? recipients.ToList();
            using (var encodeInfoHandle = new CmsgEnvelopedEncodeInfoHandle(recipientsCollection, contentEncryptionOid, unprotectedAttributes, strictRfc5753)) {
                using (var cmsgHandle = PinvokeUtil.DoPinvokeWithException(() => NativeCryptMsgPinvoke.CryptMsgOpenToEncode(
                    CryptEncodingTypeFlags.PKCS_7_ASN_ENCODING | CryptEncodingTypeFlags.X509_ASN_ENCODING,
                    CryptMsgFlags.None, CryptMsgType.CMSG_ENVELOPED, encodeInfoHandle,
                    contentTypeOid, IntPtr.Zero), h => !h.Result.IsInvalid)) {

                    
                    var encodedInputData = Array.Empty<byte>();
                    try {
                        var inputData = plaintextContent.ReadUnprotected();
                        encodedInputData = contentTypeOid != KnownOids.GenericCmsData
                            ? inputData : Asn1Util.EncodeAsPrimitiveOctetString(inputData);
                        Array.Clear(inputData, 0, inputData.Length);

                        PinvokeUtil.DoPinvokeWithException(() =>
                                NativeCryptMsgPinvoke.CryptMsgUpdate(cmsgHandle, encodedInputData, (uint) encodedInputData.Length, true),
                            r => CryptoExceptionFactory.forErrorCode(r.Win32ErrorCode));
                    } finally {
                        Array.Clear(encodedInputData, 0, encodedInputData.Length);
                    }
                    

                    var encodedSize = 0;
                    PinvokeUtil.DoPinvokeWithException(() =>
                            NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(cmsgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, null, ref encodedSize),
                        r => r.Result || r.Win32ErrorCode == (int) CryptoResult.ERROR_MORE_DATA);

                    var encodedData = new byte[encodedSize];
                    PinvokeUtil.DoPinvokeWithException(() =>
                        NativeCryptMsgPinvoke.CryptMsgGetParamByteArray(cmsgHandle, CryptMsgParamType.CMSG_CONTENT_PARAM, 0, encodedData, ref encodedSize));
                    return encodedData;
                }
            }
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
        
        public static int GetPublicKeyLengthBits(X509Certificate2 cert) {
            BCryptKeyHandle keyHandle;
            if (!NativeCryptPinvoke.CryptImportPublicKeyInfoEx2(
                CryptEncodingTypeFlags.X509_ASN_ENCODING | CryptEncodingTypeFlags.PKCS_7_ASN_ENCODING,
                new CryptPublicKeyInfoHandle(cert), CryptFindOIDInfoKeyTypeFlag.CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, IntPtr.Zero, out keyHandle)) {
                return -1;
            }

            using (keyHandle) {
                int keyLengthBits;
                int outputDataSize;
                if (NTStatusUtil.NTStatus.STATUS_SUCCESS != NativeBCryptPinvoke.BCryptGetPropertyInt32(
                    keyHandle, "KeyLength", out keyLengthBits, 4, out outputDataSize, 0)) {
                    return -1;
                }

                return keyLengthBits;
            }
        }
        
        public static bool IsKeyAgreeSupported(X509Certificate2 cert) {
            var pubKey = ImportPublicKey(cert);
            if (pubKey.KeyHandle.IsInvalid) {
                return false;
            }

            using (var pubKeyHandle = pubKey.KeyHandle) {
                CngInterfaceIdentifier cngInterfaceType;
                if (AvailableCngAlgorithms.TryGetValue(pubKey.CngAlgorithmName, out cngInterfaceType)) {
                    return cngInterfaceType == CngInterfaceIdentifier.BCRYPT_SECRET_AGREEMENT_INTERFACE;
                }
                
                int keyLength;
                int outputDataSize;
                if (NTStatusUtil.NTStatus.STATUS_SUCCESS != NativeBCryptPinvoke.BCryptGetPropertyInt32(
                    pubKeyHandle, "KeyLength", out keyLength, 4, out outputDataSize, 0)) {
                    if (NTStatusUtil.NTStatus.STATUS_SUCCESS != NativeBCryptPinvoke.BCryptGetPropertyInt32(
                        pubKeyHandle, "KeyStrength", out keyLength, 4, out outputDataSize, 0)) {
                        return false;
                    }
                }

                IntPtr algorithmProviderNativeHandle;
                if (NTStatusUtil.NTStatus.STATUS_SUCCESS != NativeBCryptPinvoke.BCryptGetPropertyIntPtr(
                    pubKeyHandle, "ProviderHandle", out algorithmProviderNativeHandle, IntPtr.Size, out outputDataSize, 0)) {
                    return false;
                }

                BCryptKeyHandle keyPairHandle;
                if (NTStatusUtil.NTStatus.STATUS_SUCCESS != NativeBCryptPinvoke.BCryptGenerateKeyPair(
                    new BCryptAlgorithmHandle(algorithmProviderNativeHandle, false), out keyPairHandle, keyLength, 0)) {
                    return false;
                }

                using (keyPairHandle) {
                    // Very slow - invocation time increases dramatically, after a bunch of invocations: Maybe waiting for entropy?
                    if (NTStatusUtil.NTStatus.STATUS_SUCCESS != NativeBCryptPinvoke.BCryptFinalizeKeyPair(keyPairHandle, 0)) {
                        return false;
                    }

                    BCryptSecretHandle secretHandle;
                    if (NTStatusUtil.NTStatus.STATUS_SUCCESS == NativeBCryptPinvoke.BCryptSecretAgreement(
                        keyPairHandle, pubKeyHandle, out secretHandle, 0)) {
                        secretHandle.Dispose();
                        return true;
                    }

                    return false;
                }
            }
        }
        

        public static bool IsEncryptionSupported(X509Certificate2 cert) {
            var pubKey = ImportPublicKey(cert);
            if (pubKey.KeyHandle.IsInvalid) {
                return false;
            }

            using (var keyHandle = pubKey.KeyHandle) {
                CngInterfaceIdentifier cngInterfaceType;
                if (AvailableCngAlgorithms.TryGetValue(pubKey.CngAlgorithmName, out cngInterfaceType)) {
                    return cngInterfaceType == CngInterfaceIdentifier.BCRYPT_CIPHER_INTERFACE 
                           || cngInterfaceType == CngInterfaceIdentifier.BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
                }
                
                int blocksize;
                int outputDataSize;
                if (NTStatusUtil.NTStatus.STATUS_SUCCESS != NativeBCryptPinvoke.BCryptGetPropertyInt32(
                    keyHandle, "BlockLength", out blocksize, 4, out outputDataSize, 0)) {
                    blocksize = 32;
                }

                var emptyData = new HGlobalHandle(0);
                var outputData = new HGlobalHandle(blocksize);
                return NTStatusUtil.NTStatus.STATUS_SUCCESS == NativeBCryptPinvoke.BCryptEncrypt(keyHandle, emptyData, emptyData.Size, IntPtr.Zero, emptyData, 0, outputData, outputData.Size, out outputDataSize, 2);
            }
        }
        
        public static KeyInfo QueryCertificatePrivateKey(X509Certificate2 cert) {
            // see also:
            //  - https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
            //  - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgetprovparam
            
            var cspParams = GetParameters(cert);
            if (cspParams == null) {
                return null;
            }

            var pubKeyInfo = QueryCertificatePublicKey(cert);
            
            bool? isHardware = null;
            bool? isRemovable = null;
            bool canExport = false;
            bool canKeyAgree = pubKeyInfo.CanKeyAgree;
            
            // 0: Ncrypt Key Provider (no indication) - let's assume CanDecrypt until we've got more information
            // 1: We can decrypt, the key is of type Exchange
            bool canKeyTransfer = cspParams.KeyNumber == (int)KeyNumber.Exchange || (cspParams.KeyNumber == 0 && pubKeyInfo.CanKeyTransfer);
            bool canSign = cspParams.KeyNumber == (int)KeyNumber.Signature || (cspParams.KeyNumber == 0 && pubKeyInfo.CanSign);


            NcryptOrContextHandle providerHandle = null;
            
            // CryptNG
            if (cspParams.KeyNumber == 0) {
                NCryptContextHandle ncryptProviderHandle = null;
                DoNcryptWithException(() => NativeNCryptPinvoke.NCryptOpenStorageProvider(out ncryptProviderHandle, cspParams.ProviderName, 0));
                providerHandle = ncryptProviderHandle;
            } else {
                CryptContextHandle cspHandle = null;
                PinvokeUtil.DoPinvokeWithException(() => NativeLegacyCapiPinvoke.CryptAcquireContext(out cspHandle, null, cspParams.ProviderName, cspParams.ProviderType, CryptAcquireContextFlags.CRYPT_SILENT | CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT));
                providerHandle = cspHandle;
            }

            using (providerHandle) {
                byte[] providerImplementation = GetNcryptOrCspProperty(providerHandle, "Impl Type", CryptGetProvParamType.PP_IMPTYPE, true);
                isHardware = providerImplementation.Length > 0 && (providerImplementation[0] & 0x1) == 0x1;
                isRemovable = providerImplementation.Length > 0 && (providerImplementation[0] & 0x8) == 0x8;
                canExport = !isHardware.Value;
            }
            
            
            var optOwner = IntPtr.Zero;
            var keyHandleRaw = IntPtr.Zero;
            var keySpec = CryptPrivateKeySpec.UNDEFINED;
            var mustFreeHandle = false;

            PinvokeUtil.DoPinvokeWithException(() => NativeCertPinvoke.CryptAcquireCertificatePrivateKey(cert.Handle,
                    CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_USE_PROV_INFO_FLAG
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_NO_HEALING
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
                    | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG,
                    ref optOwner, out keyHandleRaw, out keySpec, out mustFreeHandle),
                isSuccessOrMissingKeyPredicate);

            using (NcryptOrContextHandle keyHandle = NcryptOrContextHandle.of(keyHandleRaw, mustFreeHandle, keySpec)) {
                if (keyHandle.IsInvalid) {
                    return new KeyInfo(canKeyAgree, canKeyTransfer, canSign, canExport, false, isHardware, isRemovable);
                }
                
                byte[] keyImplementation = GetNcryptOrCspProperty(keyHandle, "Impl Type", CryptGetProvParamType.PP_IMPTYPE, true);
                if (keyImplementation.Length > 0) {
                    isHardware = keyImplementation.Length > 0 && (keyImplementation[0] & 0x1) == 0x1;
                    isRemovable = keyImplementation.Length > 0 && (keyImplementation[0] & 0x8) == 0x8;
                    canExport = !isHardware.Value;
                }

                var ncryptKeyHandle = keyHandle as NCryptContextHandle;
                if (ncryptKeyHandle != null) {
                    byte[] exportPolicy = GetNcryptProperty(ncryptKeyHandle, "Export Policy", NCryptGetPropertyFlags.NCRYPT_SILENT_FLAG);
                    canExport = exportPolicy.Length == 0 ? canExport : (exportPolicy[0] & 0x1) == 0x1; 
                    
                    byte[] keyUsagePolicy = GetNcryptProperty(ncryptKeyHandle, "Key Usage", NCryptGetPropertyFlags.NCRYPT_SILENT_FLAG);
                    canKeyTransfer = keyUsagePolicy.Length == 0 ? canKeyTransfer : (keyUsagePolicy[0] & 0x1) == 0x1;
                    canKeyAgree = keyUsagePolicy.Length == 0 ? canKeyAgree : (keyUsagePolicy[0] & 0x4) == 0x4;
                    canSign = keyUsagePolicy.Length    == 0 ? canSign : (keyUsagePolicy[0]    & 0x2) == 0x2;
                }
            }
            
            return new KeyInfo(canKeyAgree, canKeyTransfer, canSign, canExport, true, isHardware, isRemovable);
        }

        public static KeyInfo QueryCertificatePublicKey(X509Certificate2 cert) {
            return new KeyInfo(
                IsKeyAgreeSupported(cert), IsEncryptionSupported(cert), false /*tbd*/,
                true, true, false, false);
        }

        private static PortableProtectedBinary DecryptEnvelopedCmsImpl(CryptMsgHandle cryptMsgHandle, CryptMsgRecipient recipient, bool alwaysSilent, string optContextDescription, IntPtr optOwner, PortableProtectedString optPin
        ) {
            if (recipient == null) {
                throw new ArgumentNullException("recipient");
            }

            if (recipient.RecipientCert == null) {
                throw new ArgumentException("recipient.RecipientCert == null", "recipient");
            }
            
            var silent = alwaysSilent || optPin != null;
            var keyHandleRaw = IntPtr.Zero;
            var keySpec = CryptPrivateKeySpec.UNDEFINED;
            var mustFreeHandle = false;
            PinvokeUtil.DoPinvokeWithException(() => NativeCertPinvoke.CryptAcquireCertificatePrivateKey(recipient.RecipientCert.Handle,
                CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG
                | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_USE_PROV_INFO_FLAG
                | CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
                | (optOwner != IntPtr.Zero && ! silent ? CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG : 0) 
                | (silent ? CryptAcquireCertificatePrivateKeyFlags.CRYPT_ACQUIRE_SILENT_FLAG : 0), 
                ref optOwner, out keyHandleRaw, out keySpec, out mustFreeHandle));
 
            using (var keyHandle = NcryptOrContextHandle.of(keyHandleRaw, mustFreeHandle, keySpec)) {
                if (optPin != null) SetNcryptOrCspPropertyUA(
                    keyHandle, "SmartCardPin",
                    keyHandle.KeySpec == CryptPrivateKeySpec.AT_KEYEXCHANGE ? CryptSetProvParamType.PP_KEYEXCHANGE_PIN : CryptSetProvParamType.PP_SIGNATURE_PIN,
                    silent, optPin);

                if (optContextDescription != null) SetNcryptOrCspPropertyU(keyHandle, "Use Context", CryptSetProvParamType.PP_PIN_PROMPT_STRING, silent, optContextDescription);

                if (recipient is CryptMsgRecipientKeyTrans) {
                    return DecryptCryptMsgKeyTransRecipient(cryptMsgHandle, keyHandle, recipient.RecipientIndex);
                }
                
                var recipientKeyAgree = recipient as CryptMsgRecipientKeyAgree;
                if (recipientKeyAgree != null) {
                    return DecryptCryptMsgKeyAgreeRecipient(cryptMsgHandle, keyHandle, recipientKeyAgree);
                } 
                
                throw new NotSupportedException("Unsupported recipient type: " + recipient);
            }
        }

        private static IReadOnlyList<X509Certificate2> GetAvailableCertificates(X509Certificate2Collection additionalCerts) {
            return GetAvailableCertificates(additionalCerts.Cast<X509Certificate2>());
        }
        
        private static IReadOnlyList<X509Certificate2> GetAvailableCertificates(IEnumerable<X509Certificate2> additionalCerts) {
            using (var userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine)) {
                userStore.Open(OpenFlags.ReadOnly);
                machineStore.Open(OpenFlags.ReadOnly);
                
                var userStoreCerts = userStore.Certificates.Cast<X509Certificate2>();
                var machineStoreCerts = machineStore.Certificates.Cast<X509Certificate2>();

                return additionalCerts.Concat(userStoreCerts).Concat(machineStoreCerts)
                                      .DistinctBy(c => c.Thumbprint)
                                      .ToList().AsReadOnly();
            }
        }

        private static void SetNcryptOrCspPropertyU(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam,  bool silent, string value) {
            SetNcryptOrCspProperty(handle, ncryptProperty, cspParam, silent, Encoding.Unicode.GetBytes(value + "\0"));
        }
        
        private static void SetNcryptOrCspPropertyUA(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam,  bool silent, PortableProtectedString value) {
            var valueBytes = handle is NCryptContextHandle ? value.ReadUnprotectedUtf16NullTerminated() : value.ReadUnprotectedAsciiNullTerminated();
            
            try {
                SetNcryptOrCspProperty(handle, ncryptProperty, cspParam, silent, valueBytes);
            } finally {
                Array.Clear(valueBytes, 0, valueBytes.Length);
            }
        }
        
        private static void SetNcryptOrCspProperty(NcryptOrContextHandle handle, string ncryptProperty, CryptSetProvParamType cspParam, bool silent, byte[] value) {
            if (handle is NCryptContextHandle) {
                SetNcryptProperty((NCryptContextHandle)handle, ncryptProperty, value, silent ? NCryptSetPropertyFlags.NCRYPT_SILENT_FLAG : NCryptSetPropertyFlags.None);
            } else {
                SetCspProperty((CryptContextHandle)handle, cspParam, value);
            }
        }

        private static byte[] GetNcryptOrCspProperty(NcryptOrContextHandle handle, string ncryptProperty, CryptGetProvParamType cspParam, bool silent) {
            if (handle is NCryptContextHandle) {
                return GetNcryptProperty((NCryptContextHandle)handle, ncryptProperty, silent ? NCryptGetPropertyFlags.NCRYPT_SILENT_FLAG : NCryptGetPropertyFlags.None);
            } else {
                return GetCspProperty((CryptContextHandle)handle, cspParam);
            }
        }

    }
}