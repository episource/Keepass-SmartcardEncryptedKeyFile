using System;
using System.Drawing;
using System.Resources;

using KeePass;

namespace Episource.KeePass.EKF.Resources {
    public static class KeepassBuiltinImage {
        private static readonly Lazy<ResourceManager> ResourceManager = new Lazy<ResourceManager>(
            () => new ResourceManager("KeePass.Properties.Resources", typeof(Program).Assembly));
        
        public static Image Get(string resourceName) {
            return ResourceManager.Value.GetObject(resourceName) as Image;
        }
    }
}