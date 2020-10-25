using System.Security;

namespace KeePassStore {
    public class KeePassSecret {
        public SecureString Password { get; set; }
        public string UserName { get; set; }
        public string KeePassGroupPath { get; set; }
    }
}