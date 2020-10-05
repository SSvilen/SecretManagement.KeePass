using KeePassLib;
using System.Linq;
using System.Management.Automation;
using ValidationClasses;

namespace KeePassStore {
    [Cmdlet(VerbsCommon.New, "KeePassSecretStore")]
    public sealed class KeePassSecretStore : PSCmdlet {
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateFileNotExists]
        public string Path { get; set; }

        [Parameter(Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string MasterPassword { get; set; }

        [Parameter(Position = 2, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string KeyFile { get; set; }

        [Parameter()]
        public SwitchParameter WindowsUserAccount { get; set; }

        protected override void BeginProcessing() {
            var keysEnumerator = MyInvocation.BoundParameters.Keys.GetEnumerator();
            bool parameterSpecified = false;

            do {
                string[] requiredParameters = new string[] { "MasterPassword", "KeyFile", "WindowsUserAccount" };
                if (requiredParameters.Any(parameter => parameter == keysEnumerator.Current)) parameterSpecified = true;
            } while (keysEnumerator.MoveNext() && parameterSpecified == false);

            if (parameterSpecified == false) {
                ThrowTerminatingError(
                    new ErrorRecord(
                        exception: new PSArgumentException("At least on of the parameters 'MasterPassword', 'KeyFile', 'WindowsUserAccount' should be specified."),
                        errorId: "KeePassSecretStoreNoMasterKeySpecified",
                        errorCategory: ErrorCategory.InvalidArgument,
                        this));
            }
        }
        protected override void EndProcessing() {
            KeePassLib.Serialization.IOConnectionInfo iOConnectionInfo = new KeePassLib.Serialization.IOConnectionInfo {
                Path = Path
            };
            KeePassLib.Keys.CompositeKey compositeKey = new KeePassLib.Keys.CompositeKey();

            if (string.IsNullOrEmpty(MasterPassword) == false) compositeKey.AddUserKey(new KeePassLib.Keys.KcpPassword(MasterPassword));
            if (string.IsNullOrEmpty(KeyFile) == false) compositeKey.AddUserKey(new KeePassLib.Keys.KcpKeyFile(KeyFile, true));
            if (WindowsUserAccount.IsPresent == true) compositeKey.AddUserKey(new KeePassLib.Keys.KcpUserAccount());

            PwDatabase pwDatabase = new PwDatabase();
            pwDatabase.New(ioConnection: iOConnectionInfo, pwKey: compositeKey);
            pwDatabase.Save(new KeePassLib.Interfaces.NullStatusLogger());
        }
    }
}
