using System.Windows.Forms;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed partial class PinPromptDialogFactory {
        public PinPromptDialogResult ShowDialog(Form owner = null, string description = "", bool isRetry = false) {
            var pinPromptDialog = new PinPromptDialog(owner, description, isRetry);
            pinPromptDialog.ShowDialog();
            return pinPromptDialog.result;
        }
    }
}