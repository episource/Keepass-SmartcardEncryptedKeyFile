using System;

using EpiSource.KeePass.Ekf.Crypto;

using KeePassLib.Security;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed partial class PinPromptDialog {
        
        public sealed class PinPromptDialogResult {

            public PinPromptDialogResult(PortableProtectedString pin, bool rememberPinRequested) {
                this.pin = pin;
                this.rememberPinRequested = rememberPinRequested;
            }

            private readonly PortableProtectedString pin;
            private readonly bool rememberPinRequested;

            public bool IsCanceled { get { return pin == null; } }
            public bool PinAvailable { get { return this.pin != null; } }
            public bool RememberPinRequested { get { return this.rememberPinRequested; } }
            public PortableProtectedString Pin {
                get {
                    if (this.pin == null) {
                        throw new InvalidOperationException("Pin not available.");
                    }
                    return this.pin;
                }
            }

        }
    }
}