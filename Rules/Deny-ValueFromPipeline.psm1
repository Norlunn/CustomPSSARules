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
            $ParamBlock = $ScriptBlockAst.FindAll( { $args[0] -is [System.Management.Automation.Language.ParamBlockAst] }, $false)
            $Params = $ScriptBlockAst.FindAll( { $args[0] -is [System.Management.Automation.Language.ParameterAst] }, $false)

            $ParamEval = New-Object -TypeName System.Collections.ArrayList
            foreach ($Param in $Params) {
                $ValueFromPipeline = '$false'
                $ParameterSetName = "NoParamSetName"

                $IndexValueFromPipeline = $Param.Attributes.NamedArguments.ArgumentName.ToLower().IndexOf('valuefrompipeline')
                if ($IndexValueFromPipeline -ge 0) {
                    $ValueFromPipeline = $Param.Attributes.NamedArguments.Argument[$IndexValueFromPipeline].Extent.Text
                }

                $IndexParameterSetName = $Param.Attributes.NamedArguments.ArgumentName.ToLower().IndexOf('parametersetname')
                if ($IndexParameterSetName -ge 0) {
                    $ParameterSetName = $Param.Attributes.NamedArguments.Argument[$IndexParameterSetName].Extent.Text
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
            $PSCmdlet.ThrowTerminatingError($_);
        }
    }
}