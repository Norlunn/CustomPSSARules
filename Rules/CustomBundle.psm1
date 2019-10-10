#requires -version 3.0
function Measure-MultipleValueFromPipeline {
<#
.SYNOPSIS
    There should not be more than one parameter with the same object type, in each parameter set, that accepts value from pipeline

.DESCRIPTION
    There should not be more than one parameter with the same object type, in each parameter set, that accepts value from pipeline
#>
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {
        try {

            # TODO: Identify violations
            $Params = $ScriptBlockAst.FindAll( { $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $false)

            $ParamEval = New-Object -TypeName System.Collections.ArrayList
            foreach ($Param in $Params) {
                $ValueFromPipeline = '$false'
                $ParameterSetName = "NoParamSetName"

                $ArgumentName = $Param.Attributes.NamedArguments.ArgumentName
                if ($ArgumentName)
                {
                    $IndexValueFromPipeline = $ArgumentName.ToLower().IndexOf('valuefrompipeline')
                    if ($IndexValueFromPipeline -ge 0) {
                        $ValueFromPipeline = $Param.Attributes.NamedArguments.Argument[$IndexValueFromPipeline].Extent.Text
                    }

                    $IndexParameterSetName = $Param.Attributes.NamedArguments.ArgumentName.ToLower().IndexOf('parametersetname')
                    if ($IndexParameterSetName -ge 0) {
                        $ParameterSetName = $Param.Attributes.NamedArguments.Argument[$IndexParameterSetName].Extent.Text
                    }
                }

                [Void]$ParamEval.Add([PSCustomObject]@{
                        Parameter         = $Param.name.VariablePath.UserPath
                        ValueFromPipeline = $ValueFromPipeline
                        ParameterSetName  = $ParameterSetName
                    })
            }

            $UniqueParameterSets = @($ParamEval.ParameterSetName | Select-Object -Unique)
            foreach ($ParamSet in $UniqueParameterSets) {
                $ThisSet = $ParamEval | Where-Object { $_.ParameterSetName -eq $ParamSet }
                $TrueCount = $ThisSet | Where-Object { $_.ValueFromPipeline -ne '$false' }

                if ($TrueCount.Count -gt 1){
                    New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                        Message  = "There were $($TrueCount.Count) parameters in the same parameter set ($ParamSet) where ValueFromPipeline was specified as true. You shouldn't have more than one. The offending parameters are $($TrueCount.Parameter -join ', ')"
                        Extent   = $ParamBlock.Extent
                        RuleName = $PSCmdlet.MyInvocation.InvocationName
                        Severity = 'Warning'
                    }
                }
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
            #$_ | Select-Object -Property * | Out-File D:\repos\CustomPSSARules\error.txt -Force
        }
    }
}

function Measure-ParameterPascal {
<#
.SYNOPSIS
    Parameters should use PascalCase

.DESCRIPTION
    Parameters should use PascalCase. Since this is hard to check, only the first letter will be checked. Must be uppercase.
#>
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {
        try {

            $ParameterAst = $ScriptBlockAst.FindAll( { $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $false)
            foreach ($Param in $ParameterAst)
            {
                $Name = $Param.Name.VariablePath.UserPath
                $FirstLetter = [Int][byte][char]$Name[0]
                if ($FirstLetter -in 97..122){
                    New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                        Message = "PowerShell parameters should be in PascalCase. The parameter $Name do not start with an uppercase letter."
                        Extent = $Param.Name.Extent
                        RuleName = $PSCmdlet.MyInvocation.InvocationName
                        Severity = 'Warning'
                    }
                }
            }
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
            #$_ | Select-Object -Property * | Out-File D:\repos\CustomPSSARules\error.txt -Force
        }
    }
}

function Measure-KeywordLowercase {
<#
.SYNOPSIS
    Keywords in PowerShell should be in lowercase.

.DESCRIPTION
    Keywords in PowerShell should be in lowercase.

.EXAMPLE
    Measure-KeywordLowercase -ScriptBlockAst $ScriptBlockAst

.INPUTS
    [System.Management.Automation.Language.ScriptBlockAst]

.OUTPUTS
    [Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord[]]

.NOTES

#>
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {
        try {
            #region function
            [ScriptBlock]$Predicate = {
                param ([System.Management.Automation.Language.Ast]$Ast)

                [bool]$returnValue = $false

                if ($Ast -is [System.Management.Automation.Language.FunctionDefinitionAst])
                {
                    [System.Management.Automation.Language.FunctionDefinitionAst]$FunctionAst = $Ast;
                    if ($FunctionAst.Extent.Text.Substring(0, 8) -cne 'function')
                    {
                        $returnValue = $true
                    }
                }

                return $returnValue
            }

            [System.Management.Automation.Language.FunctionDefinitionAst[]]$Asts = $ScriptBlockAst.FindAll($Predicate, $false)

            foreach ($Ast in $Asts)
            {
                [int]$startLineNumber =  $ast.Extent.StartLineNumber
                [int]$endLineNumber = $ast.Extent.EndLineNumber
                [int]$startColumnNumber = $ast.Extent.StartColumnNumber
                [int]$endColumnNumber = $ast.Extent.EndColumnNumber
                [string]$correction = 'function' + $ast.Extent.Text.Substring(8, $ast.Extent.Text.Length - 8)
                $correctionExtent = New-Object 'Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent' $startLineNumber,$endLineNumber,$startColumnNumber,$endColumnNumber,$correction,$description
                $suggestedCorrections = New-Object System.Collections.ObjectModel.Collection['Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent']
                [void]$suggestedCorrections.add($correctionExtent)

                New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                    Message = "Function definition keyword 'function' should be all lowercase for function '$($Ast.Name)'"
                    Extent = $Ast.Extent
                    RuleName = $PSCmdlet.MyInvocation.InvocationName
                    Severity = 'Warning'
                    SuggestedCorrections = $suggestedCorrections
                }
            }

            #endregion function

            #region foreach
            [ScriptBlock]$Predicate = {
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

            [System.Management.Automation.Language.ForEachStatementAst[]]$Asts = $ScriptBlockAst.FindAll($Predicate, $false)

            foreach ($Ast in $Asts)
            {
                [int]$startLineNumber =  $ast.Extent.StartLineNumber
                [int]$endLineNumber = $ast.Extent.EndLineNumber
                [int]$startColumnNumber = $ast.Extent.StartColumnNumber
                [int]$endColumnNumber = $ast.Extent.EndColumnNumber
                [string]$correction = 'foreach' + $ast.Extent.Text.Substring(7, $ast.Extent.Text.Length - 7)
                $correctionExtent = New-Object 'Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent' $startLineNumber,$endLineNumber,$startColumnNumber,$endColumnNumber,$correction,$description
                $suggestedCorrections = New-Object System.Collections.ObjectModel.Collection['Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.CorrectionExtent']
                [void]$suggestedCorrections.add($correctionExtent)

                New-Object -TypeName Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord -Property @{
                    Message = "Foreach definition keyword 'foreach' should be all lowercase for '$($Ast.Extent.Text -split "`n" | Select-Object -First 1)'"
                    Extent = $Ast.Extent
                    RuleName = $PSCmdlet.MyInvocation.InvocationName
                    Severity = 'Warning'
                    SuggestedCorrections = $suggestedCorrections
                }
            }

            #endregion foreach

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
                        'contains', 'notcontains', 'in', 'notin',
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

#region CommunityAnalyzerRules
# Some functions from https://github.com/PowerShell/PSScriptAnalyzer/blob/master/Tests/Engine/CommunityAnalyzerRules/CommunityAnalyzerRules.psm1


function Measure-RequiresRunAsAdministrator
{
<#
.SYNOPSIS
    Uses #Requires -RunAsAdministrator instead of your own methods.
.DESCRIPTION
    The #Requires statement prevents a script from running unless the Windows PowerShell version, modules, snap-ins, and module and snap-in version prerequisites are met.
    From Windows PowerShell 4.0, the #Requires statement let script developers require that sessions be run with elevated user rights (run as Administrator).
    Script developers does not need to write their own methods any more.
    To fix a violation of this rule, please consider to use #Requires -RunAsAdministrator instead of your own methods.
.EXAMPLE
    Measure-RequiresRunAsAdministrator -ScriptBlockAst $ScriptBlockAst
.INPUTS
    [System.Management.Automation.Language.ScriptBlockAst]
.OUTPUTS
    [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]]
.NOTES
    None
#>
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    Process
    {
        $results = @()

        try
        {
            #region Define predicates to find ASTs.

            # Finds specific method, IsInRole.
            [ScriptBlock]$predicate1 = {
                param ([System.Management.Automation.Language.Ast]$Ast)

                [bool]$returnValue = $false

                if ($Ast -is [System.Management.Automation.Language.MemberExpressionAst])
                {
                    [System.Management.Automation.Language.MemberExpressionAst]$meAst = $ast;
                    if ($meAst.Member -is [System.Management.Automation.Language.StringConstantExpressionAst])
                    {
                        [System.Management.Automation.Language.StringConstantExpressionAst]$sceAst = $meAst.Member;
                        if ($sceAst.Value -eq "isinrole")
                        {
                            $returnValue = $true;
                        }
                    }
                }

                return $returnValue
            }

            # Finds specific value, [system.security.principal.windowsbuiltinrole]::administrator.
            [ScriptBlock]$predicate2 = {
                param ([System.Management.Automation.Language.Ast]$Ast)

                [bool]$returnValue = $false

                if ($ast -is [System.Management.Automation.Language.AssignmentStatementAst])
                {
                    [System.Management.Automation.Language.AssignmentStatementAst]$asAst = $Ast;
                    if ($asAst.Right.ToString() -eq "[system.security.principal.windowsbuiltinrole]::administrator")
                    {
                        $returnValue = $true
                    }
                }

                return $returnValue
            }

            #endregion

            #region Finds ASTs that match the predicates.

            [System.Management.Automation.Language.Ast[]]$methodAst     = $ScriptBlockAst.FindAll($predicate1, $true)
            [System.Management.Automation.Language.Ast[]]$assignmentAst = $ScriptBlockAst.FindAll($predicate2, $true)

            if ($null -ne $ScriptBlockAst.ScriptRequirements)
            {
                if ((!$ScriptBlockAst.ScriptRequirements.IsElevationRequired) -and
                    ($methodAst.Count -ne 0) -and ($assignmentAst.Count -ne 0))
                {
                    $result = New-Object `
                                -Typename "Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord" `
                                -ArgumentList $Messages.MeasureRequiresRunAsAdministrator,$assignmentAst.Extent,$PSCmdlet.MyInvocation.InvocationName,Information,$null
                    $results += $result
                }
            }
            else
            {
                if (($methodAst.Count -ne 0) -and ($assignmentAst.Count -ne 0))
                {
                    $result = New-Object `
                                -Typename "Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord" `
                                -ArgumentList $Messages.MeasureRequiresRunAsAdministrator,$assignmentAst.Extent,$PSCmdlet.MyInvocation.InvocationName,Information,$null
                    $results += $result
                }
            }

            return $results

            #endregion
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
}

function Measure-RequiresModules
{
<#
.SYNOPSIS
    Uses #Requires -Modules instead of Import-Module.
.DESCRIPTION
    The #Requires statement prevents a script from running unless the Windows PowerShell version, modules, snap-ins, and module and snap-in version prerequisites are met.
    From Windows PowerShell 3.0, the #Requires statement let script developers specify Windows PowerShell modules that the script requires.
    To fix a violation of this rule, please consider to use #Requires -Modules { <Module-Name> | <Hashtable> } instead of using Import-Module.
.EXAMPLE
    Measure-RequiresModules -ScriptBlockAst $ScriptBlockAst
.INPUTS
    [System.Management.Automation.Language.ScriptBlockAst]
.OUTPUTS
    [Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]]
.NOTES
    None
#>
    [CmdletBinding()]
    [OutputType([Microsoft.Windows.Powershell.ScriptAnalyzer.Generic.DiagnosticRecord[]])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]
        $ScriptBlockAst
    )

    Process
    {
        $results = @()

        try
        {
            #region Define predicates to find ASTs.

            # Finds specific command name, import-module.
            [ScriptBlock]$predicate = {
                param ([System.Management.Automation.Language.Ast]$Ast)

                [bool]$returnValue = $false

                if ($Ast -is [System.Management.Automation.Language.CommandAst])
                {
                    [System.Management.Automation.Language.CommandAst]$cmdAst = $Ast;
                    if ($null -ne $cmdAst.GetCommandName())
                    {
                        if ($cmdAst.GetCommandName() -eq "import-module")
                        {
                            $returnValue = $true
                        }
                    }
                }

                return $returnValue
            }

            #endregion

            #region Finds ASTs that match the predicates.

            [System.Management.Automation.Language.Ast[]]$asts = $ScriptBlockAst.FindAll($predicate, $true)

            if ($null -ne $ScriptBlockAst.ScriptRequirements)
            {
                if (($ScriptBlockAst.ScriptRequirements.RequiredModules.Count -eq 0) -and
                    ($null -ne $asts))
                {
                    foreach ($ast in $asts)
                    {
                        $result = New-Object `
                                -Typename "Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord" `
                                -ArgumentList $Messages.MeasureRequiresModules,$ast.Extent,$PSCmdlet.MyInvocation.InvocationName,Information,$null

                        $results += $result
                    }
                }
            }
            else
            {
                if ($null -ne $asts)
                {
                    foreach ($ast in $asts)
                    {
                        $result = New-Object `
                                -Typename "Microsoft.Windows.PowerShell.ScriptAnalyzer.Generic.DiagnosticRecord" `
                                -ArgumentList $Messages.MeasureRequiresModules,$ast.Extent,$PSCmdlet.MyInvocation.InvocationName,Information,$null

                        $results += $result
                    }
                }
            }

            return $results

            #endregion
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
}

#endregion

Export-ModuleMember -Function Measure*