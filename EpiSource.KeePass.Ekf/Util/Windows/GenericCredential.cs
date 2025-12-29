using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public sealed class GenericCredential {
        private readonly string comment;
        private readonly string targetName;
        private readonly string targetAlias;
        private readonly string userName;
        private readonly PortableProtectedBinary credentialBlob;

        private IDictionary<string, IList<byte>> attributes;

        public GenericCredential(string targetName, PortableProtectedBinary credentialBlob) {
            this.targetName = targetName;
            this.credentialBlob = credentialBlob;
            this.comment = "KeePass EKF Credential";
            this.targetAlias = "";
            this.userName = "";
            this.attributes = new ReadOnlyDictionary<string, IList<byte>>(new Dictionary<string, IList<byte>>());
        }
        
        public GenericCredential(string targetName, PortableProtectedBinary credentialBlob, string userName, string targetAlias, string comment)
            : this(targetName, credentialBlob, userName, targetAlias, comment, null, true) { }
        public GenericCredential(string targetName, PortableProtectedBinary credentialBlob, string userName, string targetAlias, string comment, IDictionary<string, IList<byte>> attributes)
            : this(targetName, credentialBlob, userName, targetAlias, comment, attributes, true) { }

        private GenericCredential(string targetName, PortableProtectedBinary credentialBlob, string userName, string targetAlias, string comment, IDictionary<string, IList<byte>> attributes, bool copyAttributes) {
            this.comment = comment;
            this.targetName = targetName;
            this.targetAlias = targetAlias;
            this.userName = userName;
            this.credentialBlob = credentialBlob;

            if (attributes == null) {
                this.attributes = new ReadOnlyDictionary<string, IList<byte>>(new Dictionary<string, IList<byte>>());
            } else if (copyAttributes) {
                var attributesCopy = new Dictionary<string, IList<byte>>(attributes.Count);
                foreach (var attr in attributes) {
                    attributesCopy.Add(attr.Key, new ReadOnlyCollection<byte>(new List<byte>(attr.Value)));
                }
                this.attributes = new ReadOnlyDictionary<string, IList<byte>>(attributesCopy);
            } else {
                this.attributes = attributes.IsReadOnly ? attributes : new ReadOnlyDictionary<string, IList<byte>>(attributes);
            }
        }

        public GenericCredential(GenericCredential credential) {
            this.comment = credential.Comment;
            this.targetName = credential.TargetName;
            this.targetAlias = credential.TargetAlias;
            this.userName = credential.UserName;
            this.credentialBlob = credential.CredentialBlob;
        }

        public GenericCredential SetComment(string comment) {
            return new GenericCredential(this.targetName, this.credentialBlob, this.userName, this.targetAlias, comment, this.attributes, false);
        }

        public GenericCredential SetUserName(string userName) {
            return new GenericCredential(this.targetName, this.credentialBlob, userName, this.targetAlias, this.comment, this.attributes, false);
        }

        public GenericCredential SetTargetAlias(string targetAlias) {
            return new GenericCredential(this.targetName, this.credentialBlob, this.userName, this.targetAlias, this.comment, this.attributes, false);
        }

        public GenericCredential SetCredentialBlob(PortableProtectedBinary credentialBlob) {
            return new GenericCredential(this.targetName, credentialBlob, this.userName, this.targetAlias, this.comment, this.attributes, false);
        }

        public GenericCredential AddAttribute(string name, IList<byte> value) {
            var nextAttributes = new Dictionary<string, IList<byte>>(this.attributes);
            nextAttributes.Add(name, value);
            return new GenericCredential(this.targetName, this.credentialBlob, this.userName, this.targetAlias, this.comment, nextAttributes, false);
        }
        
        public GenericCredential SetAttribute(string name, IList<byte> value) {
            var nextAttributes = new Dictionary<string, IList<byte>>(this.attributes);
            nextAttributes[name] = value;
            return new GenericCredential(this.targetName, this.credentialBlob, this.userName, this.targetAlias, this.comment, nextAttributes, false);
        }
        
        public GenericCredential RemoveAttribute(string name) {
            var nextAttributes = new Dictionary<string, IList<byte>>(this.attributes);
            nextAttributes.Remove(name);
            return new GenericCredential(this.targetName, this.credentialBlob, this.userName, this.targetAlias, this.comment, nextAttributes, false);
        }

        public void Save(WinCred.CredentialPersistence persistence = WinCred.CredentialPersistence.LocalMachine) {
            WinCred.WriteGenericCredential(this,persistence);
        }
            
        public string Comment { get { return this.comment; } }
        public string TargetName { get { return this.targetName; } }
        public string TargetAlias { get { return this.targetAlias; } }
        public string UserName { get { return this.userName; } }
        public PortableProtectedBinary CredentialBlob { get { return this.credentialBlob; } }
        public IDictionary<string, IList<byte>> Attributes { get { return this.attributes; } }
        
    }
}