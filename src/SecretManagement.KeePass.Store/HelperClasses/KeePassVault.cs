using System;
using System.IO;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using Newtonsoft.Json;
using System.Management.Automation;
using KeePassLib;
using static KeePassStore.Utilities;
using KeePassLib.Collections;
using System.Security;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace KeePassStore {
    public static class KeePassVault {
        public static PwDatabase OpenKeePassVault(string VaultName, PSCmdlet psCmdlet) {
            psCmdlet.WriteVerbose($"Trying to open the {VaultName}.config file.");
            
            string keePassConfigurationPath = Path.Combine(localConfigurationPath, $"{VaultName}.config");
            
            psCmdlet.WriteDebug($"The Vault configuration file is {keePassConfigurationPath}.");

            StoreConfiguration storeConfiguration = JsonConvert.DeserializeObject<StoreConfiguration>(File.ReadAllText(keePassConfigurationPath));

            psCmdlet.WriteVerbose($"Creating the parameters required for openining the KeePass database.");

            IOConnectionInfo iOConnectionInfo = new IOConnectionInfo {
                Path = storeConfiguration.KdbxPath
            };


            CompositeKey compositeKey = new CompositeKey();

            if (storeConfiguration.MasterPassword == true) compositeKey.AddUserKey(new KcpPassword(PromptForPassword(psCmdlet)));
            if (string.IsNullOrEmpty(storeConfiguration.KckKeyFile) == false) compositeKey.AddUserKey(new KcpKeyFile(storeConfiguration.KckKeyFile, true));
            if (storeConfiguration.KcpUserAccount == true) compositeKey.AddUserKey(new KcpUserAccount());

            psCmdlet.WriteVerbose($"Trying to open the database.");

            PwDatabase pwDatabase = new PwDatabase();
            pwDatabase.Open(iOConnectionInfo, compositeKey, new KeePassLib.Interfaces.NullStatusLogger());

            if (pwDatabase.IsOpen == false) {
                throw new Exception("Could not open the file!");
            }

            psCmdlet.WriteVerbose($"Database opened.");

            return pwDatabase;
        }

        public static bool CloseKeePassVault(PwDatabase pwDatabase) {
            pwDatabase.Close();
            return !pwDatabase.IsOpen;
        }

        public static PSCredential ReadSecret(string SecretName, PwDatabase pwDatabase) {
            PwObjectList<PwEntry> pwObjectList = pwDatabase.RootGroup.GetEntries(true);
            SecureString secureString = new SecureString();

            foreach (var pwentry in pwObjectList) {
                if (pwentry.Strings.GetSafe("Title").ToString() == SecretName) {
                    char[] chars = pwentry.Strings.GetSafe("Password").ReadChars();
                    string username = pwentry.Strings.GetSafe("Username").ToString();

                    foreach (var c in chars) {
                        secureString.AppendChar(c);
                    }
                    return new PSCredential(username, secureString);
                }
            }

            return PSCredential.Empty;
        }

        public static void SetSecret(PwDatabase pwDatabase,Dictionary<string, object> pwEntryProperties) {
            if (pwEntryProperties.ContainsKey("KeePassGroupPath")) {
                MatchCollection matchCollection = Regex.Matches(pwEntryProperties["KeePassGroupPath"].ToString(),"\\w+");
                if(matchCollection.Count > 0) 
            } else {

                PwEntry pwEntry = new PwEntry()
            }
        }
    }
}

