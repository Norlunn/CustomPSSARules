function Deny-ValueFromPipeline {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {
        try {

            # TODO: Identify violations

            New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                Message = "This is a very valuable message."
                Extent = $ScriptBlockAst.Extent
                RuleName = $PSCmdlet.MyInvocation.InvocationName
                Severity = 'Warning'
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_);
        }
    }
}