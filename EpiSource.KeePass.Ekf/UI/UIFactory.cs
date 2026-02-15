using EpiSource.KeePass.Ekf.Plugin;

namespace EpiSource.KeePass.Ekf.UI {
    public class UIFactory {
        private readonly PluginConfiguration pluginConfiguration;

        public UIFactory(PluginConfiguration pluginConfiguration) {
            this.pluginConfiguration = pluginConfiguration;

            this.EditEncryptedKeyFileDialog = new EditEncryptedKeyFileDialogFactory(this);
            this.PinPromptDialog = new PinPromptDialogFactory();
            this.SmartcardOperationDialog = new SmartcardOperationDialogFactory(pluginConfiguration);
            this.SmartcardRequiredDialog = new SmartcardRequiredDialogFactory(this);
        }

        public EditEncryptedKeyFileDialogFactory EditEncryptedKeyFileDialog {
            get;
            private set;
        }

        public PinPromptDialogFactory PinPromptDialog {
            get;
            private set;
        }
        
        public SmartcardOperationDialogFactory SmartcardOperationDialog {
            get;
            private set;
        }

        public SmartcardRequiredDialogFactory SmartcardRequiredDialog {
            get;
            private set;
        }
    }
}