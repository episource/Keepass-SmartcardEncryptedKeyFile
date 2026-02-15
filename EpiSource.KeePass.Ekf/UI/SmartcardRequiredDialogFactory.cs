using System.Linq;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed partial class SmartcardRequiredDialogFactory {
        
        private readonly UIFactory uiFactory;

        public SmartcardRequiredDialogFactory(UIFactory uiFactory) {
            this.uiFactory = uiFactory;
        }
        
        public IKeyPair ChooseKeyPairForDecryption(EncryptedKeyFile ekf, Form owner = null) {
            var keyPairProvider = this.uiFactory.SmartcardOperationDialog
                .DoCryptoWithMessagePumpShort(ct => DefaultKeyPairProvider.FromEncryptedKeyFile(ekf));
            return ChooseKeyPairForDecryption(keyPairProvider, owner);
        }

        public IKeyPair ChooseKeyPairForDecryption(IKeyPairProvider keyProvider, Form owner = null) {
            var candidates = keyProvider.GetAuthorizedKeyPairs();
            if (candidates.Count == 0) {
                return null;
            }

            var readyKeyPairs = candidates
                                .Where(kp => kp.KeyPair.IsReadyForDecryptCms)
                                .ToList();
            if (readyKeyPairs.Count == 1) {
                return readyKeyPairs.First().KeyPair;
            }

            var dialog = new SmartcardRequiredDialog(owner, keyProvider, this.uiFactory);
            var result = dialog.ShowDialog(owner);
            if (result != DialogResult.OK || dialog.keyListView.CheckedItems.Count == 0) {
                return null;
            }

            return dialog.keyListView.CheckedItems.Cast<ListViewItem>()
                         .Select(i => i.Tag as KeyPairModel)
                         // ReSharper disable once PossibleNullReferenceException
                         .Select(m => m.KeyPair).First();
        }
    }
}