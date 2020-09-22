#
# Module manifest for module 'SecretsManagement.KeePass'
#
# Generated by: jgrote
#
# Generated on: 2/10/2020
#

@{

# Script module or binary module file associated with this manifest.
# RootModule = ''

# Version number of this module.
ModuleVersion = '0.0.3.1'

# Supported PSEditions
CompatiblePSEditions = @('Desktop','Core')

# ID used to uniquely identify this module
GUID = '14f945da-777e-4f2b-9c79-b59287d19478'

# Author of this module
Author = 'Justin Grote'

# Copyright statement for this module
Copyright = '(c) 2020 Justin Grote. All rights reserved.'

# Description of the functionality provided by this module
Description = 'A Proof of Concept for a Keepass Secrets Management provider. See the README.MD in the module for more details. PS5.1 only due to module used'

# Modules that must be imported into the global environment prior to importing this module
NestedModules = @(
    './SecretManagement.KeePass.Extension/SecretManagement.KeePass.Extension.psd1'
    './PoshKeePass/PoshKeePass.psd1'
)
RequiredModules = @(
    'Microsoft.Powershell.SecretManagement'
)
PowershellVersion = '5.1'
FunctionsToExport = @()
CmdletsToExport   = @()
VariablesToExport = @()
AliasesToExport   = @()
}

