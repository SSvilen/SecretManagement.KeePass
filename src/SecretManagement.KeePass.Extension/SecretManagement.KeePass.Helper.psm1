function Open-KeePassVault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VaultName
    )
    try {
        $Script:pwDatabase = [KeePassStore.KeePassVault]::OpenKeePassVault($VaultName, $PSCmdlet)
    } catch {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [Exception]::new("Could not open the Vault $VaultName. Reason: $($_.Exception.Message)"),
                '1000',
                [System.Management.Automation.ErrorCategory]::OpenError,
                $VaultName
            )
        )
    }
}