@{
    ModuleVersion      = '0.0.3'
    RequiredAssemblies = '..\KeePassStore.dll'
    RootModule         = '.\SecretManagement.KeePass.Extension.psm1'
    FunctionsToExport  = @('Set-Secret', 'Get-Secret', 'Remove-Secret', 'Get-SecretInfo', 'Test-SecretVault')
}