using System.Collections.Generic;

namespace Episource.KeePass.EKF.UI {
    public interface IKeyPairProvider {
        IList<KeyPairModel> GetAvailableKeyPairs();
        IList<KeyPairModel> GetAuthorizedKeyPairs();
        bool Refresh();
    }
}