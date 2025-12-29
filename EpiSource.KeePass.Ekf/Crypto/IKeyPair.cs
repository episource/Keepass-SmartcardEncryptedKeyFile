using System.Security.Cryptography.X509Certificates;

namespace EpiSource.KeePass.Ekf.Crypto {
    public interface IKeyPair {
        /// <summary>
        /// Retrieves whether the key pair is provided by a smart card.
        /// </summary>
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        /// <returns>
        /// <code>true</code> when backed by smartcard or other other secure hardware security module,
        /// <code>false</code> if not backed by hardware and <code>null</code> if unknown.
        /// </returns>
        bool? IsSmartcard { get; }
        
        /// <summary>
        /// Retrieves whether the key container is accessible. Operations using the private key might,
        /// still require confirmation before succeeding. Removable smartcards must be connected before the key
        /// container accessible. Encryption operation might be available even if the key container is not accessible.
        /// This will be reported by <see cref="IsReadyForEncrypt"/>. 
        /// </summary>
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        /// <returns>
        /// <code>true</code> when the key container is accessible, otherwise <code>false</code>.
        /// </returns>
        bool IsAccessible { get; }
        
        /// <summary>
        /// Retrieves whether the decrypt operation is likely to succeed now. Some hardware devices might require
        /// confirmation for this operation to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if decryption is likely to succeed, otherwise <code>false</code>.
        /// </returns>
        bool IsReadyForDecrypt { get; }
        
        /// <summary>
        /// Retrieves whether the decrypt CMS operation is likely to succeed now. Some hardware devices might require
        /// confirmation for this operation to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if decryption is likely to succeed, otherwise <code>false</code>.
        /// </returns>
        bool IsReadyForDecryptCms { get; }
        
        /// <summary>
        /// Retrieves whether the encrypt operation is likely to succeed now. Some hardware devices might require
        /// confirmation for this operation to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if encryption is likely to succeed, otherwise <code>false</code>.
        /// </returns>
        bool IsReadyForEncrypt { get; }
        
        /// <summary>
        /// Retrieves whether the encrypt CMS operation is likely to succeed now. Some hardware devices might require
        /// confirmation for this operation to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if encryption is likely to succeed, otherwise <code>false</code>.
        /// </returns>
        bool IsReadyForEncryptCms { get; }
        
        /// <summary>
        /// Retrieves whether the sign operation is likely to succeed now. Some hardware devices might require
        /// confirmation for this operation to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if signing is likely to succeed, otherwise <code>false</code>.
        /// </returns>
        bool IsReadyForSign { get; }
        
        /// <summary>
        /// Retrieves whether the private key can be exported from the smartcard. A smartcard is only safe if the
        /// private key cannot leave the smartcard.
        /// </summary>
        /// <returns>
        /// <code>false</code> when the smart card is safe and the private key cannot be exported, <code>null</code> if
        /// unknown and otherwise <code>true</code>.
        /// </returns>
        bool? CanExportPrivateKey { get; }

        /// <summary>
        /// Retrieves whether the smartcard is hot-pluggable can can be attached/removed while the system is up. In case
        /// of removable smart cards, any operation may fail at any time because the card has been detached.
        /// </summary>
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        /// <remarks>
        /// Blocks if a busy hardware device is involved.
        /// </remarks>
        /// <returns>
        /// <code>true</code> if the smart card can be attached/removed while the system is up, <code>false</code> if
        /// not. <code>null</code> if unknown.
        /// </returns>
        bool? IsRemovable { get; }
        
        /// <summary>
        /// Retrieves whether in principle the decrypt operation is supported by this key pair.
        /// </summary>
        /// <returns>
        /// <code>true</code> if decryption is eventually possible with this key pair, otherwise <code>false</code>
        /// </returns>
        bool CanDecrypt { get; }
        
        /// <summary>
        /// Retrieves whether in principle the decrypt CMS operation is supported by this key pair.
        /// </summary>
        /// <returns>
        /// <code>true</code> if decryption is eventually possible with this key pair, otherwise <code>false</code>
        /// </returns>
        bool CanDecryptCms { get; }
        
        /// <summary>
        /// Retrieves whether in principle the encrypt operation is supported by this key pair.
        /// </summary>
        /// <returns>
        /// <code>true</code> if encryption is eventually possible with this key pair, otherwise <code>false</code>
        /// </returns>
        bool CanEncrypt { get; }
        
        /// <summary>
        /// Retrieves whether in principle the encrypt operation is supported by this key pair.
        /// </summary>
        /// <returns>
        /// <code>true</code> if encryption is eventually possible with this key pair, otherwise <code>false</code>
        /// </returns>
        bool CanEncryptCms { get; }

        /// <summary>
        /// Retrieves whether this key can be used or key agreement.
        /// </summary>
        bool CanKeyAgree { get; }
        
        /// <summary>
        /// Retrieves whether in principle the sign operation is supported by this key pair.
        /// </summary>
        /// <returns>
        /// <code>true</code> if signing is eventually possible with this key pair, otherwise <code>false</code>
        /// </returns>
        bool CanSign { get; }

        /// <summary>
        /// Retrieves a X509 certificate wrapping the current key pair.
        /// </summary>
        /// <returns>
        /// A <see cref="X509Certificate2"/> certificate instance.
        /// </returns>
        X509Certificate2 Certificate { get; }
}

}