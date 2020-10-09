using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using KeePassLib.Keys;
using Newtonsoft.Json;

namespace KeePassStore {
    internal class Utilities {
        private readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static string SecureStringToString(SecureString secureString) {
            IntPtr intPtr = IntPtr.Zero;
            try {
                intPtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(intPtr);
            } finally {
                Marshal.ZeroFreeGlobalAllocUnicode(intPtr);
            }
        }

        public static void SaveStoreConfiguration(IEnumerable<IUserKey> UserKeys, string Name) {
            StoreConfiguration storeConfiguration = new StoreConfiguration();

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

            string KeePassConfigurationPath;

            if (IsWindows) {
                var locationPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                KeePassConfigurationPath = Path.Combine(locationPath, "Microsoft", "PowerShell", "keepassstore", $"{Name}.config");
            }
            else {
                var locationPath = Environment.GetEnvironmentVariable("HOME");
                KeePassConfigurationPath = Path.Combine(locationPath, ".keepassstore", $"{Name}.config");
            }

            File.WriteAllText(KeePassConfigurationPath, JsonConvert.SerializeObject(storeConfiguration));
        }
        
        internal static void SetStoreConfiguration(Dictionary<string, object> boundParameters) {
            
        }

        private class StoreConfiguration {
            public StoreConfiguration() {
            }

            public bool MasterPassword { get; internal set; }
            public string KckKeyFile { get; internal set; }
            public bool KcpUserAccount { get; internal set; }
        }
    }
}
