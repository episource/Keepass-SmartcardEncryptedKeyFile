using System.Collections.Generic;

namespace EpiSource.KeePass.Ekf.UI {
    public interface IKeyPairProvider {
        IList<KeyPairModel> GetAvailableKeyPairs();
        IList<KeyPairModel> GetAuthorizedKeyPairs();
        bool Refresh();
        bool Refresh(IKeyPairProvider other);
    }
}