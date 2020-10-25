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

        public static KeePassSecret ReadSecret(string SecretName, PwDatabase pwDatabase, string KeePassGroupPath) {
            PwGroup targetPWGroup = FindTargetPWGroup(pwDatabase, KeePassGroupPath, false);

            PwObjectList<PwEntry> searchResult = new PwObjectList<PwEntry>();
            SearchPasswordEntries(SecretName, targetPWGroup, out searchResult);


            if (searchResult.UCount == 0) throw new Exception($"No entries found for {SecretName}.");
            if (searchResult.UCount > 1) throw new Exception($"Multiple ambiguous entries found for {SecretName}, please remove the duplicate entry");

            List<KeePassSecret> secretsList = new List<KeePassSecret>();

            KeePassSecret keePassSecret = new KeePassSecret();
            SecureString secureString = new SecureString();

            char[] chars = searchResult.GetAt(0).Strings.GetSafe("Password").ReadChars();
            string username = searchResult.GetAt(0).Strings.GetSafe("UserName").ReadString();

            foreach (var c in chars) {
                secureString.AppendChar(c);
            }

            keePassSecret.Password = secureString;
            keePassSecret.UserName = username;
            keePassSecret.KeePassGroupPath = targetPWGroup.GetFullPath("/", false);

            return keePassSecret;
        }

        public static void SetSecret(PwDatabase pwDatabase, Dictionary<string, object> pwEntryProperties) {
            PwGroup targetPWGroup;

            if (pwEntryProperties.ContainsKey("KeePassGroupPath")) {
                bool createKeePassGroup = pwEntryProperties.ContainsKey("CreateKeePassGroup");
                targetPWGroup = FindTargetPWGroup(pwDatabase, pwEntryProperties["KeePassGroupPath"].ToString(), createKeePassGroup);
            } else {
                targetPWGroup = pwDatabase.RootGroup;
            }

            SearchPasswordEntries(pwEntryProperties["Name"].ToString(), targetPWGroup, out PwObjectList<PwEntry> searchResult);

            // Found an exisiting entry.
            if (searchResult.UCount == 0) {
                PwEntry pwEntryToAdd = new PwEntry(true, true);
                foreach (string key in pwEntryProperties.Keys) {
                    switch (key) {
                        case "Name":
                            pwEntryToAdd.Strings.Set("Title", new KeePassLib.Security.ProtectedString(true, pwEntryProperties[key].ToString()));
                            continue;
                        case "Secret":
                            pwEntryToAdd.Strings.Set("Password", new KeePassLib.Security.ProtectedString(true, SecureStringToString((SecureString)pwEntryProperties[key])));
                            continue;
                        default:
                            pwEntryToAdd.Strings.Set(key, new KeePassLib.Security.ProtectedString(true, string.Join(",", pwEntryProperties[key].ToString())));
                            break;
                    }
                }

                targetPWGroup.AddEntry(pwEntryToAdd, false);
                pwDatabase.Save(new KeePassLib.Interfaces.NullStatusLogger());
            } else if (searchResult.UCount == 1) {
                foreach (string key in pwEntryProperties.Keys) {
                    switch (key) {
                        case "Secret":
                            searchResult.GetAt(0).Strings.Set("Password", new KeePassLib.Security.ProtectedString(true, SecureStringToString((SecureString)pwEntryProperties[key])));
                            continue;
                        default:
                            searchResult.GetAt(0).Strings.Set(key, new KeePassLib.Security.ProtectedString(true, pwEntryProperties[key].ToString()));
                            break;
                    }
                }

                pwDatabase.Save(new KeePassLib.Interfaces.NullStatusLogger());
            } else {
                throw new Exception($"Multiple secrets with name {pwEntryProperties["Name"]} found in KeePass Group {targetPWGroup.Name}!");
            }
        }

        private static PwGroup FindTargetPWGroup(PwDatabase pwDatabase, string keePassGroupPath, bool createKeePassGroup) {
            PwGroup pwGroupFound = pwDatabase.RootGroup.FindCreateSubTree(keePassGroupPath, new char[] { '/' }, createKeePassGroup);

            if (pwGroupFound != null) return pwGroupFound;

            throw new Exception($"KeePass Group {keePassGroupPath} was not found!");
        }

        private static void SearchPasswordEntries(string secretName, PwGroup targetPWGroup, out PwObjectList<PwEntry> searchResult) {
            PwObjectList<PwEntry> pwEntryList = new PwObjectList<PwEntry>();

            foreach (PwEntry pwEntry in targetPWGroup.GetEntries(false)) {
                if (pwEntry.Strings.GetSafe("Title").ReadString().ToLower() == secretName.ToLower()) pwEntryList.Add(pwEntry);
            }

            searchResult = pwEntryList;
        }
        public static bool CloseKeePassVault(PwDatabase pwDatabase) {
            pwDatabase.Close();
            return !pwDatabase.IsOpen;
        }

    }
}

