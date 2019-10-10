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
            #region comparison operators
            [ScriptBlock]$Predicate = {
                param ([System.Management.Automation.Language.Ast]$Ast)

                [bool]$returnValue = $false

                if ($Ast -is [System.Management.Automation.Language.BinaryExpressionAst])
                {
                    [System.Management.Automation.Language.BinaryExpressionAst]$OpAst = $Ast;

                    $Operators = @(
                        'eq', 'ne', 'gt', 'lt', 'le', 'ge',
                        'like', 'notlike',
                        'match', 'notmatch',
                        'replace', 'or', 'and', 'is', 'isnot',
                        'contains', 'notcontains', 'in', 'notin'
                        'ceq', 'cne', 'cgt', 'clt', 'cle', 'cge',
                        'clike', 'cnotlike',
                        'cmatch', 'cnotmatch'
                    )

                    if (($OpAst.ErrorPosition.Text -replace '-') -in $Operators -and ($OpAst.ErrorPosition.Text -replace '-') -cnotin $Operators)
                    {
                        $returnValue = $true
                    }
                }

                return $returnValue
            }

            [System.Management.Automation.Language.BinaryExpressionAst[]]$Asts = $ScriptBlockAst.FindAll($Predicate, $false)

            foreach ($Ast in $Asts)
            {
                [int]$startLineNumber =  $ast.Extent.StartLineNumber
                [int]$endLineNumber = $ast.Extent.EndLineNumber
                [int]$startColumnNumber = $ast.Extent.StartColumnNumber
                [int]$endColumnNumber = $ast.Extent.EndColumnNumber
                [string]$correction = $ast.Extent.Text -replace "$($ast.ErrorPosition.Text)", "$($ast.ErrorPosition.Text.ToLower())"
                $correctionExtent = New-Object 'Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent' $startLineNumber,$endLineNumber,$startColumnNumber,$endColumnNumber,$correction,$description
                $suggestedCorrections = New-Object System.Collections.ObjectModel.Collection['Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent']
                [void]$suggestedCorrections.add($correctionExtent)

                New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                    Message = "All comparison operators should be lowercase. Offending operator: $($Ast.ErrorPosition.Text)"
                    Extent = $Ast.Extent
                    RuleName = $PSCmdlet.MyInvocation.InvocationName
                    Severity = 'Warning'
                    SuggestedCorrections = $suggestedCorrections
                }
            }

            #endregion comparison operators
        }
        catch {
            $_ | Select-Object -Property * | Out-File D:\repos\CustomPSSARules\error.txt -Force
            $PSCmdlet.ThrowTerminatingError($_);
        }
    }
}