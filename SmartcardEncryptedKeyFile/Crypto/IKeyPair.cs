using System.Security.Cryptography.X509Certificates;

namespace Episource.KeePass.EKF.Crypto {
    public interface IKeyPair {
        /// <summary>
        /// Retrieves whether the key pair is provided by a smart card.
        /// </summary>
        /// <returns>
        /// <code>true</code> when backed by smart card, <code>false</code> otherwise.
        /// </returns>
        bool IsSmartcard { get; }
        
        /// <summary>
        /// Is smartcard available for sign and decryption operations.
        /// </summary>
        /// <returns>
        /// <code>true</code> when smartcard is available, otherwise <code>false</code>.
        /// </returns>
        bool IsSmartcardAvailable { get; }

        /// <summary>
        /// Retrieves whether the private key can be exported from the smartcard. A smartcard is only safe if the
        /// private key cannot leave the smartcard.
        /// </summary>
        /// <returns>
        /// <code>false</code> when the smart card is safe and the private key cannot be exported, otherwise
        /// <code>true</code>.
        /// </returns>
        bool CanExportPrivateKey { get; }

        /// <summary>
        /// Retrieves whether the smartcard is hot-pluggable can can be attached/removed while the system is up. In case
        /// of removable smart cards, any operation may fail at any time because the card has been detached.
        /// </summary>
        /// <returns>
        /// <code>true</code> if the smart card can be attached/removed while the system is up, otherwise
        /// <code>false</code>.
        /// </returns>
        bool IsRemovable { get; }

        /// <summary>
        /// Retrieves whether the sign operation is likely to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if signing is possible with the current state of the smart card, otherwise
        /// <code>false</code>.
        /// </returns>
        bool CanSign { get; }

        /// <summary>
        /// Retrieves whether the encrypt operation is likely to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if encryption is possible with the current state of the smart card, otherwise
        /// <code>false</code>.
        /// </returns>
        bool CanEncrypt { get; }
        
        /// <summary>
        /// Retrieves whether the decrypt operation is likely to succeed.
        /// </summary>
        /// <returns>
        /// <code>true</code> if decryption is possible with the current state of the smart card, otherwise
        /// <code>false</code>.
        /// </returns>
        bool CanDecrypt { get; }
        
        /// <summary>
        /// Retrieves a X509 certificate wrapping the current key pair.
        /// </summary>
        /// <returns>
        /// A <see cref="X509Certificate2"/> certificate instance.
        /// </returns>
        X509Certificate2 Certificate { get; }
}

}