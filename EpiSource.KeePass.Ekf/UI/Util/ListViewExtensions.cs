using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace EpiSource.KeePass.Ekf.UI.Util {
    public static class ListViewExtensions {
        public static IEnumerable<T> ItemTags<T>(this ListView listView) {
            return listView.Items
                    .Cast<ListViewItem>()
                    .Where(item => item.Tag != null)
                    .Select(item => item.Tag)
                    .Cast<T>();
        }
    }
}