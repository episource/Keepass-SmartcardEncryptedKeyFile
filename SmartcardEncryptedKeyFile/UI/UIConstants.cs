using System.Drawing;
using System.Windows.Forms;

namespace Episource.KeePass.EKF.UI {
    public static class UIConstants {
        // height chosen to match a single line text box
        public const int DefaultButtonHeight = 22;
        public const int DefaultButtonWidth = 75;

        public const int MaxAutoWidth = 800;
        
        // https://stackoverflow.com/a/29766847
        public const AutoScaleMode AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
        public static readonly SizeF AutoScaleDimensions = new SizeF(6F, 13F);
    }
}