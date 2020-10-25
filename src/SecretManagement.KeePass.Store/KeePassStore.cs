using KeePassLib;
using System.Linq;
using System.Management.Automation;
using System.Security;

namespace KeePassStore {
    [Cmdlet(VerbsCommon.Add, "KeePassSecretStore")]
    public sealed class AddKeePassSecretStore : PSCmdlet {
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateFileExists]
        public string KdbxPath { get; set; }

        [Parameter(Position = 1, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter(Position = 2, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public SecureString MasterPassword { get; set; }

        [Parameter(Position = 3, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
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
                Path = KdbxPath
            };
            KeePassLib.Keys.CompositeKey compositeKey = new KeePassLib.Keys.CompositeKey();

            try {
                if (MasterPassword != null) compositeKey.AddUserKey(new KeePassLib.Keys.KcpPassword(Utilities.SecureStringToString(MasterPassword)));
                if (string.IsNullOrEmpty(KeyFile) == false) compositeKey.AddUserKey(new KeePassLib.Keys.KcpKeyFile(KeyFile, true));
                if (WindowsUserAccount.IsPresent == true) compositeKey.AddUserKey(new KeePassLib.Keys.KcpUserAccount());

                PwDatabase pwDatabase = new PwDatabase();
                pwDatabase.Open(iOConnectionInfo, compositeKey, new KeePassLib.Interfaces.NullStatusLogger());

                if (pwDatabase.IsOpen == false) {
                    throw new System.Exception("Could not open the file!");
                }

                pwDatabase.Close();
            } catch (System.Exception) {
                throw;
            }
            try {
                Utilities.SaveStoreConfiguration(compositeKey.UserKeys, Name, KdbxPath);
            } catch (System.Exception) {

                throw;
            }
        }
    }
    [Cmdlet(VerbsCommon.New, "KeePassSecretStore")]
    public sealed class NewKeePassSecretStore : PSCmdlet {
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateFileNotExists]
        public string KdbxPath { get; set; }

        [Parameter(Position = 1, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter(Position = 2, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public SecureString MasterPassword { get; set; }

        [Parameter(Position = 3, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
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
                Path = KdbxPath
            };
            KeePassLib.Keys.CompositeKey compositeKey = new KeePassLib.Keys.CompositeKey();

            try {
                if (MasterPassword != null) compositeKey.AddUserKey(new KeePassLib.Keys.KcpPassword(Utilities.SecureStringToString(MasterPassword)));
                if (string.IsNullOrEmpty(KeyFile) == false) compositeKey.AddUserKey(new KeePassLib.Keys.KcpKeyFile(KeyFile, true));
                if (WindowsUserAccount.IsPresent == true) compositeKey.AddUserKey(new KeePassLib.Keys.KcpUserAccount());

                PwDatabase pwDatabase = new PwDatabase();
                pwDatabase.New(ioConnection: iOConnectionInfo, pwKey: compositeKey);
                pwDatabase.Save(new KeePassLib.Interfaces.NullStatusLogger());

            } catch (System.Exception) {
                throw;
            }

            //If sucessfull - save the config
            try {
                Utilities.SaveStoreConfiguration(compositeKey.UserKeys, Name, KdbxPath);
            } catch (System.Exception) {

                throw;
            }
        }
    }
    [Cmdlet(VerbsCommon.Set, "KeePassSecretStore")]
    public sealed class SetKeePassSecretStore : PSCmdlet {
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        [ValidateFileExists]
        public string KdbxPath { get; set; }

        [Parameter(Position = 1, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter(Position = 2, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public SecureString MasterPassword { get; set; }

        [Parameter(Position = 3, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
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
                Path = KdbxPath
            };
            KeePassLib.Keys.CompositeKey compositeKey = new KeePassLib.Keys.CompositeKey();

            try {
                if (MasterPassword != null) compositeKey.AddUserKey(new KeePassLib.Keys.KcpPassword(Utilities.SecureStringToString(MasterPassword)));
                if (string.IsNullOrEmpty(KeyFile) == false) compositeKey.AddUserKey(new KeePassLib.Keys.KcpKeyFile(KeyFile, true));
                if (WindowsUserAccount.IsPresent == true) compositeKey.AddUserKey(new KeePassLib.Keys.KcpUserAccount());

                PwDatabase pwDatabase = new PwDatabase();
                pwDatabase.Open(iOConnectionInfo, compositeKey, new KeePassLib.Interfaces.NullStatusLogger());

                if (pwDatabase.IsOpen == false) {
                    throw new System.Exception("Could not open the file!");
                }

                pwDatabase.Close();
            } catch (System.Exception) {
                throw;
            }
            try {
                Utilities.SaveStoreConfiguration(compositeKey.UserKeys, Name, KdbxPath);
            } catch (System.Exception) {

                throw;
            }
        }
    }
    [Cmdlet(VerbsCommon.Remove, "KeePassSecretStore")]
    public sealed class RemoveKeePassSecretStore : PSCmdlet {
        [Parameter(Position = 0, Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNullOrEmpty]
        public string Name { get; set; }

        [Parameter()]
        public SwitchParameter DeleteKDBX { get; set; }

        protected override void ProcessRecord() {
            if (DeleteKDBX.IsPresent == true) {
                Utilities.RemoveConfiguration(Name, true);
            } else {
                Utilities.RemoveConfiguration(Name);
            }
        }
    }
}