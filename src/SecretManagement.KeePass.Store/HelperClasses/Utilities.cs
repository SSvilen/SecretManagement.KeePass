using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using KeePassLib.Keys;
using Newtonsoft.Json;
using System.Management.Automation;

namespace KeePassStore {
    internal class Utilities {
        public static string localConfigurationPath;

        static Utilities() {
            bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

            if (IsWindows == true) {
                var locationPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                localConfigurationPath = Path.Combine(locationPath, "Microsoft", "PowerShell", "keepassstore");
            } else {
                var locationPath = Environment.GetEnvironmentVariable("HOME");
                localConfigurationPath = Path.Combine(locationPath, ".keepassstore");
            }

            Directory.CreateDirectory(localConfigurationPath);
        }

        public static string SecureStringToString(SecureString secureString) {
            IntPtr intPtr = IntPtr.Zero;
            try {
                intPtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(intPtr);
            } finally {
                Marshal.ZeroFreeGlobalAllocUnicode(intPtr);
            }
        }

        public static void SaveStoreConfiguration(IEnumerable<IUserKey> UserKeys, string Name, string KdbxPath) {
            StoreConfiguration storeConfiguration = new StoreConfiguration();
            storeConfiguration.KdbxPath = KdbxPath;

            foreach (var key in UserKeys.ToList()) {
                if (key.GetType() == typeof(KcpPassword)) {
                    storeConfiguration.MasterPassword = true;
                }
                if (key.GetType() == typeof(KcpKeyFile)) {
                    storeConfiguration.KckKeyFile = (key
                        as KcpKeyFile).Path;
                }
                if (key.GetType() == typeof(KcpUserAccount)) {
                    storeConfiguration.KcpUserAccount = true;
                }
            }

            string keePassConfigurationPath = Path.Combine(localConfigurationPath, $"{Name}.config");

            File.WriteAllText(keePassConfigurationPath, JsonConvert.SerializeObject(storeConfiguration));
        }
        internal static void RemoveConfiguration(string Name, bool DeleteKDBX = false) {
            File.Delete(Path.Combine(localConfigurationPath, $"{Name}.config"));

            if (DeleteKDBX) {
                string keePassConfigurationPath = Path.Combine(localConfigurationPath, $"{Name}.config");
                StoreConfiguration storeConfiguration = (StoreConfiguration)JsonConvert.DeserializeObject(File.ReadAllText(keePassConfigurationPath));
                File.Delete(storeConfiguration.KdbxPath);
            }
        }



        public static string PromptForPassword(PSCmdlet cmdlet) {
            if (cmdlet.Host == null || cmdlet.Host.UI == null) {
                throw new PSInvalidOperationException("Cannot prompt for password. No host available.");
            }

            cmdlet.Host.UI.WriteLine("A password is required for Microsoft.PowerShell.SecretStore vault.");

            SecureString password = null;
            bool isVerified;

            do {
                // Initial prompt
                cmdlet.Host.UI.WriteLine("Enter password:");
                password = cmdlet.Host.UI.ReadLineAsSecureString();

                // Verification prompt
                cmdlet.Host.UI.WriteLine("Enter password again for verification:");
                var passwordVerified = cmdlet.Host.UI.ReadLineAsSecureString();

                isVerified = ComparePasswords(password, passwordVerified);

                if (!isVerified) {
                    cmdlet.Host.UI.WriteLine("\nThe two entered passwords do not match.  Please re-enter the passwords.\n");
                }
            } while (!isVerified);

            return SecureStringToString(password);
        }

        private static bool ComparePasswords(SecureString password1, SecureString password2) {
            if (password1.Length != password2.Length) {
                return false;
            }

            IntPtr ptrPassword1 = IntPtr.Zero;
            IntPtr ptrPassword2 = IntPtr.Zero;
            try {
                ptrPassword1 = Marshal.SecureStringToCoTaskMemUnicode(password1);
                ptrPassword2 = Marshal.SecureStringToCoTaskMemUnicode(password2);
                if (ptrPassword1 != IntPtr.Zero && ptrPassword2 != IntPtr.Zero) {
                    for (int i = 0; i < (password1.Length * 2); i++) {
                        if (Marshal.ReadByte(ptrPassword1, i) != Marshal.ReadByte(ptrPassword2, i)) {
                            return false;
                        }
                    }

                    return true;
                }
            } finally {
                if (ptrPassword1 != IntPtr.Zero) {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptrPassword1);
                }

                if (ptrPassword2 != IntPtr.Zero) {
                    Marshal.ZeroFreeCoTaskMemUnicode(ptrPassword2);
                }
            }

            return false;
        }

        internal class StoreConfiguration {
            public StoreConfiguration() {
            }

            public string KdbxPath { get; set; }
            public bool MasterPassword { get; set; }
            public string KckKeyFile { get; set; }
            public bool KcpUserAccount { get; set; }
        }
    }
}

