# Changelog

## vNext (not released yet)
- Fix: `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded
- Use KeePass builtin command line parsing

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)

## v1.3.5 (2026-07-24)
- Show only certificates permitted by their key usage extension (optional, the dialog has a check box do bypass filter)
- Allow (cache) healing when querying certificate private key ([#15](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/15))
- Show private key state in edit dialog
- Add private key state "mismatch", indicating that the private key association of a locally cached certificate is broken ([#15]((https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/15)))

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.3.4 (2026-07-01) [Revoked - [#12](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/12)]
(revoked)

## v1.3.3 (2026-06-26)
- Add [(more) debug command line options](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile#debug-options)
- Fix export/import key dialog for secure desktop ([#8](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/8))
- Continue querying certificate keys when accessing private key info fails ([#5](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/5), [#6](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/6))

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.3.2 (2026-03-01)
- Fix more issues when tokens/cards are inserted or removed while "Smartcard required" dialog is shown

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- Exporting the key when generating / modifying the encrypted key file fails on secure desktop ([#8](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/8))
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.3.1 (2026-02-22)
- Fix NullReferenceException when token is inserted/removed while "Smartcard required" dialog is shown

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- Still Erratic behavior when tokens/cards are inserted or removed while "Smartcard required" dialog is shown or about to open
- Exporting the key when generating / modifying the encrypted key file fails on secure desktop ([#8](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/8))
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.3.0 (2026-02-16)
- Allow to configure smart card worker process bootstrap behavior for enterprise environments with strict threat protection - see [README](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile?tab=readme-ov-file#threat-protection-interference-failed-to-start-unblocker-process-wasnt-ready-within-s---non-default-unblocker-bootstrap-mode) and [#4](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/4).

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- Erratic behavior when tokens/cards are inserted or removed while "Smartcard required" dialog is shown or about to open (including possible NullReferenceException)
- Exporting the key when generating / modifying the encrypted key file fails on secure desktop ([#8](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/8))
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.2.1 (2026-01-19)
- Add support for ECC521 key pairs (see also [#3](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/3))
- Speed up listing of available cards/tokens: don't acquire private key handle twice for each token/card

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.2.0 (2026-01-01)
- Add support for ECC key pairs (requires YubiKey minidriver)
- Fix loading PINs first remembered with v1.1.0 of this plugin
- Let user choose a card/key for decryption, if multiple allowed cards/keys are connected (before: the first one was chosen silently)

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- ECC521 not supported - Access Violation Exception - see [#3](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/3)
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.1.0 (2025-10-31)
- Fix compatibility with [Win11 2025-10 Update KB5066835](https://learn.microsoft.com/en-us/windows/release-health/resolved-issues-windows-11-25h2#3697msgdesc) ([#2](https://github.com/episource/Keepass-SmartcardEncryptedKeyFile/issues/2))
- Fix remember PIN feature for some Win10 builds

### Known Issues
- Smart Card operations / unlocking an encrypted key file fails (with Exception dialog) if YubiKey Authenticator is running in parallel (note: only when using windows builtin smartcard driver, issue does not occur if YubiKey minidriver is installed)
- Loading PINs first remembered with v1.1.0 of this plugin fails with message "Unsupported credential protection scheme."
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v1.0.0 (2025-02-21)
- Add custom PIN prompt with universal support for secure desktop
- Add remember PIN feature

### Known Issues
- Incompatible with [Win11 2025-10 Update KB5066835](https://learn.microsoft.com/en-us/windows/release-health/resolved-issues-windows-11-25h2#3697msgdesc): no smartcard / yubikey found
- `Tools > Edit Encrypted Key File` entry has wrong state if databases with and without EKF are loaded

## v0.3.0 (2025-02-01)
- Set owner and description of native windows PIN prompt without hacks & workarounds
    * Now using Windows API (Ncrypt) directly to decrypt Encrypted Key File (before: .Net Framework classes with limited options)
- Indicate to KeePass, that Secure Desktop is only supported on Win 10
    * KeePass shows a warning when using the plugin with secure desktop enabled and does not attempt to invoke the plugin. Before one would have been locked-in (more or less) at the secure desktop when secure desktop is enabled when the EKF plugin asks for PIN input.

### Known Issues
- Secure Desktop support only for Win10

## v0.2.1 (2025-01-06)
- Write exported key files in KeyX v2 format (before: v1 format)
- Import key files like KeePass reads them (before: always read as binary)
    * After activating Enrypted Key File for a database, previously used key files of all kinds now remain valid and can be used as independent alternative to the Encrypted Key File when needed (before: only binary key files)

### Known Issues
- `Enter master key on secure desktop` compatiblity broken for current windows builds (at least Win 11 24H2). Please disable this KeePass option to use this plugin. You'll be locked-in (more or less) at the secure desktop when secure desktop is enabled and the EKF plugin needs to ask for a smartcard PIN. Use task manager to kill keepass if this happens.
- Native smartcard PIN prompt is not owned & centered properly on Win11 (at least Win 11 24H2, Win 10 works well)

## v0.2.0 (2025-01-06)
- Fix Window Defender false positives on some systems
- Show Smartcard Operation Dialog (Abort option) for more smartcard operations
- Require KeePass v2.57.1

### Known Issues
- `Enter master key on secure desktop` compatiblity broken for current windows builds (at least Win 11 24H2). Please disable this KeePass option to use this plugin.
- Imported key files that are not binary (e.g. KeyX format, Hex) can't be used after the key provider has been activated for a database. A different key will be used internally. This does not happen when using binary keyfiles (i.e. files with 32byte length).
- Native smartcard PIN prompt is not owned & centered properly on Win11 (at least Win 11 24H2, Win 10 works well)

## v0.1.1 (2020-02-29)
- Fix exception occuring when computer has not been restarted for more than 24days

## v0.1.0 (2020-02-25)
- Initial Release