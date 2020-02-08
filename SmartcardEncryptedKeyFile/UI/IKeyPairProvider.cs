using System.Collections.Generic;
using System.Data.Linq;

namespace Episource.KeePass.EKF.UI {
    public interface IKeyPairProvider {
        IList<KeyPairModel> GetAvailableKeyPairs();
        IList<KeyPairModel> GetAuthorizedKeyPairs();
        bool Refresh();
    }
}