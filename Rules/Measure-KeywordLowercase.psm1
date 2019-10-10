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
            #region if-else
            [ScriptBlock]$Predicate = {
                param ([System.Management.Automation.Language.Ast]$Ast)

                [bool]$returnValue = $false

                if ($Ast -is [System.Management.Automation.Language.IfStatementAst])
                {
                    [System.Management.Automation.Language.IfStatementAst]$IfAst = $Ast;
                    if ($IfAst.Extent.Text.Substring(0, 2) -cne 'if')
                    {
                        $returnValue = $true
                    }

                    if ($IfAst.Extent.Text -like "*elseif*" -and $IfAst.Extent.Text -cnotlike "*elseif*")
                    {
                        $returnValue = $true
                    }

                    if ($IfAst.Extent.Text -match "else(\s)*{" -and $IfAst.Extent.Text -cnotmatch "else(\s)*{")
                    {
                        $returnValue = $true
                    }
                }

                return $returnValue
            }

            [System.Management.Automation.Language.IfStatementAst[]]$Asts = $ScriptBlockAst.FindAll($Predicate, $false)

            foreach ($Ast in $Asts)
            {
                [int]$startLineNumber =  $ast.Extent.StartLineNumber
                [int]$endLineNumber = $ast.Extent.EndLineNumber
                [int]$startColumnNumber = $ast.Extent.StartColumnNumber
                [int]$endColumnNumber = $ast.Extent.EndColumnNumber
                [string]$correction = $ast.Extent.Text -replace 'if', 'if' -replace 'elseif', 'elseif' -replace 'else', 'else'
                $correctionExtent = New-Object 'Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent' $startLineNumber,$endLineNumber,$startColumnNumber,$endColumnNumber,$correction,$description
                $suggestedCorrections = New-Object System.Collections.ObjectModel.Collection['Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent']
                [void]$suggestedCorrections.add($correctionExtent)

                New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                    Message = "if-elseif-else keywords should all be in lowercase."
                    Extent = $Ast.Extent
                    RuleName = $PSCmdlet.MyInvocation.InvocationName
                    Severity = 'Warning'
                    SuggestedCorrections = $suggestedCorrections
                }
            }

            #endregion if-else
        }
        catch {
            $_ | Select-Object -Property * | Out-File D:\repos\CustomPSSARules\error.txt -Force
            $PSCmdlet.ThrowTerminatingError($_);
        }
    }
}