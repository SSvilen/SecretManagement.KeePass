using namespace KeePassStore
function Get-Secret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [string]
        $VaultName,

        [Parameter()]
        [Alias('FullPath')]
        [String] $KeePassGroupPath = '/',

        [Parameter()]
        [switch]
        $AsPSCredential,

        [Parameter()]
        [switch]
        $AsPlainText
    )

    try {
        if ($null -eq $pwDatabase) {
            $pwDatabase = Open-KeePassVault -VaultName $VaultName
        }

        $keepassGetResult = [KeePassStore.KeePassVault]::ReadSecret($Name, $pwDatabase, $KeePassGroupPath)

        if ($keepassGetResult.count -gt 1) {
            throw "Multiple ambiguous entries found for $Name, please remove the duplicate entry"
        }

        if ($AsPSCredential) {
            [pscredential]::new($keepassGetResult.username, $keepassGetResult.password)
        } elseif ($AsPlainText) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($keepassGetResult.Password)
            $plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $plainTextPassword
        } else {
            $keepassGetResult
        }
    } catch {
        throw "Could not get the KeePass entry for $name. Error was $($_.exception.message)"
    } finally {
        $pwDatabase.Close()
    }
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [SecureString]
        $Secret,

        [Parameter(Mandatory = $true)]
        [string]
        $VaultName,

        [Parameter()]
        [Alias('FullPath')]
        [String] $KeePassGroupPath = '/',

        [Parameter(Mandatory = $true, ParameterSetName = 'ExpirationDate')]
        [switch]
        $Expires,

        [Parameter(Mandatory = $true, ParameterSetName = 'ExpirationDate')]
        [DateTime]
        $ExpiryTime,

        [Parameter()]
        [switch]
        $CreateKeePassGroup,

        [Parameter()]
        [String]
        $Notes,

        [Parameter()]
        [String[]]
        $Tags,

        [Parameter()]
        [String]
        $URL,

        [Parameter()]
        [String]
        $UserName
    )

    try {
        if ($KeePassGroupPath -notmatch '^\/[\/\w]*') {
            throw "The group path that was specified is not valid. The path should have the following format: /group/group1/group2"
        }
        if ($null -eq $pwDatabase) {
            $pwDatabase = Open-KeePassVault -VaultName $VaultName
        }

        [System.Management.Automation.PSCmdlet]::CommonParameters | ForEach-Object { $PSBoundParameters.Remove($_) | Out-Null }
        [Void]$PSBoundParameters.Remove('VaultName')

        [KeePassStore.KeePassVault]::SetSecret($pwDatabase, $PSBoundParameters)
        $true
    } catch {
        thow "Could not set the secret.Error was $($_.exception.message)"
    } finally {
        $pwDatabase.Close()
    }
}

function Remove-Secret {
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if (-not (Test-SecretVault -VaultName $vaultName)) { throw "Vault ${VaultName}: Not a valid vault configuration" }
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    $GetKeePassResult = Get-KeePassEntry @KeepassParams -Title $Name
    if (-not $GetKeePassResult) { throw "No Keepass Entry named $Name found" }
    Remove-KeePassEntry @KeepassParams -KeePassEntry $GetKeePassResult -ErrorAction stop -Confirm:$false
    return $true
}

function Get-SecretInfo {
    param(
        [string]$Filter,
        [string]$VaultName = (Get-SecretVault).VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if (-not (Test-SecretVault -VaultName $vaultName)) { throw "Vault ${VaultName}: Not a valid vault configuration" }

    $KeepassParams = GetKeepassParams -VaultName $VaultName -AdditionalParameters $AdditionalParameters
    $KeepassGetResult = Get-KeePassEntry @KeepassParams | Where-Object { $_ -notmatch '^.+?/Recycle Bin/' }

    [Object[]]$secretInfoResult = $KeepassGetResult.where{
        $PSItem.Title -like $filter
    }.foreach{
        [SecretInformation]::new(
            $PSItem.Title, #string name
            [SecretType]::PSCredential, #SecretType type
            $VaultName #string vaultName
        )
    }

    [Object[]]$sortedInfoResult = $secretInfoResult | Sort-Object -Unique Name
    if ($sortedInfoResult.count -lt $secretInfoResult.count) {
        $filteredRecords = (Compare-Object $sortedInfoResult $secretInfoResult | Where-Object SideIndicator -EQ '=>').InputObject
        Write-Warning "Vault ${VaultName}: Entries with non-unique titles were detected, the duplicates were filtered out. Duplicate titles are currently not supported with this extension, ensure your entry titles are unique in the database."
        Write-Warning "Vault ${VaultName}: Filtered Non-Unique Titles: $($filteredRecords -join ', ')"
    }
    $sortedInfoResult
}

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters = (Get-SecretsVault -Name $vaultName).VaultParameters
    )

    $VaultParameters = $AdditionalParameters
    $ErrorActionPreference = 'Stop'
    Write-Verbose "SecretManagement: Testing Vault ${VaultName}"

    if (-not $VaultName) { throw 'Keepass: You must specify a Vault Name to test' }

    if (-not $VaultParameters.Path) {
        #TODO: Add ThrowUser to throw outside of module scope
        throw "Vault ${VaultName}: You must specify the Path vault parameter as a path to your KeePass Database"
    }

    if (-not (Test-Path $VaultParameters.Path)) {
        throw "Vault ${VaultName}: Could not find the keepass database $($VaultParameters.Path). Please verify the file exists or re-register the vault"
    }

    try {
        $VaultMasterKey = (Get-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction Stop).Value
        Write-Verbose "Vault ${VaultName}: Master Key found in Cache, skipping user prompt"
    } catch {
        $GetCredentialParams = @{
            Username = 'VaultMasterKey'
            Message  = "Enter the Vault Master Password for Vault $VaultName"
        }
        $VaultMasterKey = (Get-Credential @GetCredentialParams)
        if (-not $VaultMasterKey.Password) { throw 'You must specify a vault master key to unlock the vault' }
        Set-Variable -Name "Vault_$VaultName" -Scope Script -Value $VaultMasterKey
    }

    if (-not (Get-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName)) {
        New-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName -DatabasePath $AdditionalParameters.Path -UseMasterKey
        Write-Verbose "Vault ${VaultName}: A PoshKeePass database configuration was not found but was created."
        return $true
    }
    try {
        Get-KeePassEntry -DatabaseProfileName $VaultName -MasterKey $VaultMasterKey -Title '__SECRETMANAGEMENT__TESTSECRET_SHOULDNOTEXIST' -ErrorAction Stop
    } catch {
        Clear-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction SilentlyContinue
        throw $PSItem
    }

    #If the above doesn't throw an error, we are good
    return $true
}
