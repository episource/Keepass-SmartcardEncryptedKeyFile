using System;
using System.Runtime.CompilerServices;

using EpiSource.KeePass.Ekf.Crypto.Windows;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.KeePass.Ekf.Util.Windows;

using KeePass.Plugins;

using KeePassLib.Cryptography;
using KeePassLib.Utility;

namespace EpiSource.KeePass.Ekf.Util {
    public sealed class ProtectedWinCred {
        private const string ProtectionTypeAttributeName = "EpiSource_ProtectionType";
        private const byte ImplementedProtectionType = 01;
        
        private const string NonceAttributeName = "EpiSource_Nonce";
        private const string TagAttributeName = "EpiSource_Tag";

        private readonly PortableProtectedBinary key;

        public ProtectedWinCred(PortableProtectedBinary key) {
            this.key = key;
        }

        public bool IsProtected(GenericCredential credential) {
            return credential.Attributes.ContainsKey(ProtectionTypeAttributeName);
        }

        public bool IsCompatible(GenericCredential credential) {
            if (!IsProtected(credential)) {
                return true;
            }

            if (!(credential.Attributes.ContainsKey(ProtectionTypeAttributeName)
                  && credential.Attributes.ContainsKey(NonceAttributeName)
                  && credential.Attributes.ContainsKey(TagAttributeName))) {
                return false;
            }
            
            var protectionType = credential.Attributes[ProtectionTypeAttributeName];
            if (protectionType.Count != 1 || protectionType[0] != ImplementedProtectionType) {
                return false;
            }
            
            var nonce = credential.Attributes[NonceAttributeName];
            if (nonce.Count != NativeCapi.AesGcmNonceSize && nonce.Count != this.key.Length) {
                return false;
            }
            
            var tag = credential.Attributes[TagAttributeName];
            return tag.Count == 16;
        }

        public GenericCredential Protect(GenericCredential credential) {
            if (this.IsProtected(credential)) {
                return credential;
            }
            if (credential.CredentialBlob.Length > this.key.Length - 1) {
                throw new ArgumentException("Maximum supported credential length is" + this.key.Length + " bytes.");
            }

            var paddedCredentialPlaintext = new byte[this.key.Length];
            paddedCredentialPlaintext[0] = (byte)credential.CredentialBlob.Length;
            credential.CredentialBlob.ReadUnprotectedTo(paddedCredentialPlaintext, targetOffset: 1);
            var paddedCredential = PortableProtectedBinary.Move(paddedCredentialPlaintext);
            
            var encryptedCredentialBlobInfo = NativeCapi.EncryptAesGcm(paddedCredential, this.key);
            var encryptedCredentialBlob = PortableProtectedBinary.CopyOf(encryptedCredentialBlobInfo.Ciphertext);

            return credential
                   .SetCredentialBlob(encryptedCredentialBlob)
                   .SetAttribute(ProtectionTypeAttributeName, new[] { ImplementedProtectionType })
                   .SetAttribute(NonceAttributeName, encryptedCredentialBlobInfo.Nonce)
                   .SetAttribute(TagAttributeName, encryptedCredentialBlobInfo.Tag);
        }

        public GenericCredential Protect(string target, PortableProtectedString plaintextPassword, string username = "") {
            return this.Protect(new GenericCredential(target, plaintextPassword.ToUtf8()).SetUserName(username));
        }

        public GenericCredential Unprotect(GenericCredential credential) {
            if (!this.IsProtected(credential)) {
                return credential;
            }

            if (!this.IsCompatible(credential)) {
                throw new ArgumentException("Unsupported credential protection scheme.", "credential");
            }
            
            var nonce = credential.Attributes[NonceAttributeName];
            var tag = credential.Attributes[TagAttributeName];
            
            var unprotectedPaddedCredential = NativeCapi.DecryptAesGcm(credential.CredentialBlob.ReadUnprotected(), this.key, nonce, tag).ReadUnprotected();
            var plaintextCredential = PortableProtectedBinary.CopyOf(unprotectedPaddedCredential, 1, unprotectedPaddedCredential[0]);
            
            return credential
                   .SetCredentialBlob(plaintextCredential)
                   .RemoveAttribute(ProtectionTypeAttributeName)
                   .RemoveAttribute(NonceAttributeName)
                   .RemoveAttribute(TagAttributeName);
        }

        public void WriteProtectedPassword(string target, PortableProtectedString plaintextPassword, WinCred.CredentialPersistence persistence = WinCred.CredentialPersistence.LocalMachine) {
            this.Protect(target, plaintextPassword).Save(persistence);
        }

        public PortableProtectedString ReadProtectedPassword(string target) {
            GenericCredential credential;
            if (!WinCred.TryReadGenericCredential(target, out credential)) {
                return null;
            }
            return PortableProtectedString.FromUtf8(this.Unprotect(credential).CredentialBlob);
        }

        public void ClearProtectedPassword(string target) {
            WinCred.DeleteGenericCredential(target);
        }
    }
}