using System.Windows.Forms;

namespace EpiSource.KeePass.Ekf.UI.Util {
    
    public static class TimerExtensions {
        
        public static void Restart(this Timer t) {
            t.Stop();

            // restart timer: force change of interval; else interval continues!
            var modulo = t.Interval % 5;
            t.Interval += modulo == 0 ? 1 : -1 * modulo;

            t.Start();
        }
        
    }
    
}