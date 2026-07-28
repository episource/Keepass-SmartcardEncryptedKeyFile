namespace EpiSource.KeePass.Ekf.Plugin {
    public enum EkfStorePrecedence {
        /// <summary>
        /// EKF file is embedded into the KDBX file as <c>PublicCustomData</c> unencrypted header item.
        /// </summary>
        KDBX,
        
        /// <summary>
        /// EKF file is stored side-by-side within an external <c>*.ekf</c> file.
        /// </summary>
        EXTERNAL
    }
}