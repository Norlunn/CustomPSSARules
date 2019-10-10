function Measure-KeywordLowercase {
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {
        try {
            #region foreach
            [ScriptBlock]$Predicate2 = {
                param ([System.Management.Automation.Language.Ast]$Ast)

                [bool]$returnValue = $false

                if ($Ast -is [System.Management.Automation.Language.ForEachStatementAst])
                {
                    [System.Management.Automation.Language.ForEachStatementAst]$ForeachAst = $Ast;
                    if ($ForeachAst.Extent.Text.Substring(0, 7) -cne 'foreach')
                    {
                        $returnValue = $true
                    }
                }

                return $returnValue
            }

            [System.Management.Automation.Language.ForEachStatementAst[]]$Asts2 = $ScriptBlockAst.FindAll($Predicate2, $false)

            foreach ($Ast in $Asts2)
            {
                <# [int]$startLineNumber =  $ast.Extent.StartLineNumber
                [int]$endLineNumber = $ast.Extent.EndLineNumber
                [int]$startColumnNumber = $ast.Extent.StartColumnNumber
                [int]$endColumnNumber = $ast.Extent.EndColumnNumber
                [string]$correction = 'foreach' + $ast.Extent.Text.Substring(7, $ast.Extent.Text.Length - 7)
                [string]$description = 'Useful but optional description text'
                $correctionExtent = New-Object 'Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent' $startLineNumber,$endLineNumber,$startColumnNumber,$endColumnNumber,$correction,$description
                $suggestedCorrections = New-Object System.Collections.ObjectModel.Collection['Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent']
                [void]$suggestedCorrections.add($correctionExtent) #>

                New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                    Message = "Foreach $($Asts2.Count) definition keyword 'foreach' should be all lowercase for '$($Ast.Extent.Text -split "`n" | Select-Object -First 1)'"
                    Extent = $Ast.Extent
                    RuleName = $PSCmdlet.MyInvocation.InvocationName
                    Severity = 'Warning'
                    #SuggestedCorrections = $suggestedCorrections
                }
            }

            #endregion foreach
        }
        catch {
            $_ | Select-Object -Property * | Out-File D:\repos\CustomPSSARules\error.txt -Force
            $PSCmdlet.ThrowTerminatingError($_);
        }
    }
}