function enumerateencoding ([string]$EncodedCommand, [ValidateSet('UTF8','Unicode','Auto')][string]$EncodingType = 'Auto', [switch]$file) {# Evaluate and enumerate encoded PowerShell commands.

if (-not $EncodedCommand) {Write-Host -f cyan "`nUsage: enumerateencoding '<encoded string>' <-encodingtype = (UTF8|Unicode|Auto)> <-file>`n"; return}

$bytes = [System.Convert]::FromBase64String($EncodedCommand)
switch ($EncodingType) {'UTF8' {$Command = [Text.Encoding]::UTF8.GetString($bytes)}
'Unicode' {$Command = [Text.Encoding]::Unicode.GetString($bytes)}
'Auto' {$utf8 = [Text.Encoding]::UTF8.GetString($bytes)
$unicode = [Text.Encoding]::Unicode.GetString($bytes)
if ($utf8 -match '(?i)[a-z]{3,}-') {$Command = $utf8}
else {$Command = $unicode}}}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($Command, [ref]$tokens, [ref]$parseErrors)
$allVariables = [System.Collections.ArrayList]::new()

function Get-RawCommandElements {param([System.Management.Automation.Language.CommandAst]$CmdAst)
$elems = [System.Collections.ArrayList]::new()
foreach ($ce in $CmdAst.CommandElements) {$ceData = @{type = $ce.GetType().Name; text = $ce.Extent.Text}
if ($ce.PSObject.Properties['Value'] -and $null -ne $ce.Value -and $ce.Value -is [string]) {$ceData.value = $ce.Value}
if ($ce -is [System.Management.Automation.Language.CommandExpressionAst]) {$ceData.expressionType = $ce.Expression.GetType().Name}
$a=$ce.Argument;if($a){$ceData.children=@(@{type=$a.GetType().Name;text=$a.Extent.Text})}
[void]$elems.Add($ceData)}
return $elems}


function Get-RawRedirections {param($Redirections)
$result = [System.Collections.ArrayList]::new()
foreach ($redir in $Redirections) {$redirData = @{type = $redir.GetType().Name}
if ($redir -is [System.Management.Automation.Language.FileRedirectionAst]) {$redirData.append = [bool]$redir.Append
$redirData.fromStream = $redir.FromStream.ToString()
$redirData.locationText = $redir.Location.Extent.Text}
[void]$result.Add($redirData)}
return $result}


function Get-SecurityPatterns {param($A)
$p = @{}

foreach ($n in $A.FindAll({param($x)
$x -is [System.Management.Automation.Language.MemberExpressionAst] -or
$x -is [System.Management.Automation.Language.SubExpressionAst] -or
$x -is [System.Management.Automation.Language.ArrayExpressionAst] -or
$x -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
$x -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
$x -is [System.Management.Automation.Language.ParenExpressionAst]}, $true)) {

switch ($n.GetType().Name) {'InvokeMemberExpressionAst' {$p.hasMemberInvocations = $true}
'MemberExpressionAst' {$p.hasMemberInvocations = $true}
'SubExpressionAst' {$p.hasSubExpressions = $true}
'ArrayExpressionAst' {$p.hasSubExpressions = $true}
'ParenExpressionAst' {$p.hasSubExpressions = $true}
'ExpandableStringExpressionAst' {$p.hasExpandableStrings = $true}
'ScriptBlockExpressionAst' {$p.hasScriptBlocks = $true}}}

$interestingAliases = @{'cat' = 'Get-Content'
'cp' = 'Copy-Item'
'curl' = 'Invoke-WebRequest'
'del' = 'Remove-Item'
'gc' = 'Get-Content'
'gci' = 'Get-ChildItem'
'gi' = 'Get-Item'
'gp' = 'Get-ItemProperty'
'iex' = 'Invoke-Expression'
'irm' = 'Invoke-RestMethod'
'iwr' = 'Invoke-WebRequest'
'ls' = 'Get-ChildItem'
'mv' = 'Move-Item'
'ni' = 'New-Item'
'ri' = 'Remove-Item'
'rm' = 'Remove-Item'
'rv' = 'Remove-Variable'
'sal' = 'Set-Alias'
'set' = 'Set-Variable'
'sv' = 'Set-Variable'
'wget' = 'Invoke-WebRequest'}

$aliasHits = [System.Collections.ArrayList]::new()

foreach ($cmd in $A.FindAll({param($x)
$x -is [System.Management.Automation.Language.CommandAst]}, $true)) {$cmdName = $cmd.GetCommandName()

if ($cmdName -and $interestingAliases.ContainsKey($cmdName.ToLower())) {[void]$aliasHits.Add(@{alias = $cmdName
resolves = $interestingAliases[$cmdName.ToLower()]})}}

if ($aliasHits.Count -gt 0) {$p.aliasUsage = @($aliasHits)}

$encodedHits = [System.Collections.ArrayList]::new()

$encodedSwitches = @('-enc', '-ec', '-encodedcommand')

foreach ($cmd in $A.FindAll({param($x)
$x -is [System.Management.Automation.Language.CommandAst]}, $true)) {foreach ($element in $cmd.CommandElements) {$text = $element.Extent.Text.ToLower()

if ($encodedSwitches -contains $text) {[void]$encodedHits.Add(@{switch = $text
command = $cmd.Extent.Text})}}}

if ($encodedHits.Count -gt 0) {$p.hasEncodedCommand = $true
$p.encodedCommandUsage = @($encodedHits)}

$suspiciousIndicators = @('add-mppreference', 'add-type', 'amsiscanbuffer', 'amsiutils', 'assembly.load', 'assembly.loadfrom', 'bitsadmin', 'convert.frombase64string', 'createthread', 'downloadfile', 'downloadstring', 'encodedcommand', 'frombase64string', 'getprocaddress', 'gettype', 'iex', 'invoke-command', 'invoke-expression', 'invoke-restmethod', 'invoke-webrequest', 'invoke-wmimethod', 'loadlibrary', 'marshal.copy', 'marshal.readintptr', 'marshal.writeintptr', 'net.webclient', 'new-object system.net.webclient', 'reflection', 'regsvr32', 'rundll32', 'set-mppreference', 'start-bitstransfer', 'system.management.automation.amsiutils', 'system.net.webclient', 'system.reflection.assembly', 'system.runtime.interopservices.marshal', 'virtualalloc', 'writeprocessmemory')

$apiHits = [System.Collections.Generic.HashSet[string]]::new()

foreach ($node in $A.FindAll({ param($x) $true }, $true)) {$text = $node.Extent.Text.ToLowerInvariant()

foreach ($indicator in $suspiciousIndicators) {if ($text.Contains($indicator)) {[void]$apiHits.Add($indicator)}}}

if ($apiHits.Count -gt 0) {$p.suspiciousIndicatorCount = $apiHits.Count
$p.suspiciousIndicators = @($apiHits | Sort-Object)}

foreach ($cmd in $A.FindAll({param($x)
$x -is [System.Management.Automation.Language.CommandAst]}, $true))
{$name = $cmd.GetCommandName()

if ($name) {switch ($name.ToLowerInvariant()) {'invoke-expression' {[void]$apiHits.Add('invoke-expression')}
'invoke-webrequest' {[void]$apiHits.Add('invoke-webrequest')}
'invoke-restmethod' {[void]$apiHits.Add('invoke-restmethod')}
'add-type' {[void]$apiHits.Add('add-type')}}}}

if ($apiHits.Count -gt 0) {$p.suspiciousIndicators = @($apiHits | Sort-Object -Unique)}

$riskScore = 0
$riskReasons = [System.Collections.ArrayList]::new()
$riskFindings = [System.Collections.ArrayList]::new()

if ($p.hasEncodedCommand) {$riskScore += 25
[void]$riskReasons.Add('Encoded command detected')}

if ($p.hasScriptBlocks) {$riskScore += 5
[void]$riskReasons.Add('Script block usage')}

if ($p.hasSubExpressions) {$riskScore += 5
[void]$riskReasons.Add('Sub-expression usage')}

if ($p.hasMemberInvocations) {$riskScore += 5
[void]$riskReasons.Add('Member invocation usage')}

if ($p.aliasUsage) {$riskScore += ($p.aliasUsage.Count * 5)
[void]$riskReasons.Add("$($p.aliasUsage.Count) alias(es) detected")}

if ($p.suspiciousIndicators) {foreach ($indicator in $p.suspiciousIndicators) {switch ($indicator) {'amsiutils' {$riskScore += 25
[void]$riskFindings.Add(@{Indicator = 'amsiutils'
Score = 25})}
'amsiscanbuffer' {$riskScore += 25
[void]$riskFindings.Add(@{Indicator = 'amsiscanbuffer'
Score = 25})}
'virtualalloc' {$riskScore += 20
[void]$riskFindings.Add(@{Indicator = 'virtualalloc'
Score = 20})}
'createthread' {$riskScore += 20
[void]$riskFindings.Add(@{Indicator = 'createthread'
Score = 20})}
'writeprocessmemory' {$riskScore += 20
[void]$riskFindings.Add(@{Indicator = 'writeprocessmemory'
Score = 20})}
'invoke-expression' {$riskScore += 15
[void]$riskFindings.Add(@{Indicator = 'invoke-expression'
Score = 15})}
default {$riskScore += 5
[void]$riskFindings.Add(@{Indicator = $indicator
Score = 5})}}}}

$script:IndicatorCategories = @{'add-mppreference' = 'Defense Evasion'
'amsiutils' = 'Defense Evasion'
'amsiscanbuffer' = 'Defense Evasion'
'set-mppreference' = 'Defense Evasion'
'invoke-webrequest' = 'Download'
'invoke-restmethod' = 'Download'
'downloadstring' = 'Download'
'downloadfile' = 'Download'
'net.webclient' = 'Download'
'system.net.webclient' = 'Download'
'start-bitstransfer' = 'Download'
'bitsadmin' = 'Download'
'invoke-expression' = 'Execution'
'iex' = 'Execution'
'invoke-command' = 'Execution'
'add-type' = 'Execution'
'frombase64string' = 'Obfuscation'
'convert.frombase64string' = 'Obfuscation'
'encodedcommand' = 'Obfuscation'
'assembly.load' = 'Reflection'
'assembly.loadfrom' = 'Reflection'
'reflection' = 'Reflection'
'system.reflection.assembly' = 'Reflection'
'virtualalloc' = 'Memory Injection'
'createthread' = 'Memory Injection'
'writeprocessmemory' = 'Memory Injection'
'marshal.copy' = 'Memory Injection'
'marshal.readintptr' = 'Memory Injection'
'marshal.writeintptr' = 'Memory Injection'
'system.runtime.interopservices.marshal' = 'Memory Injection'
'invoke-wmimethod' = 'Lateral Movement'
'regsvr32' = 'LOLBin'
'rundll32' = 'LOLBin'}

[void]$riskReasons.Add("$($p.suspiciousIndicators.Count) suspicious indicator(s)")

$p.riskScore = $riskScore
$p.riskReasons = @($riskReasons)
$p.riskFindings = @($riskFindings)

$CategorySummary = @{}
foreach ($finding in $riskFindings) {$Category = if ($script:IndicatorCategories.ContainsKey($finding.Indicator)) {$script:IndicatorCategories[$finding.Indicator]}
else {'Other'}
if ($CategorySummary.ContainsKey($Category)) {$CategorySummary[$Category]++}
else {$CategorySummary[$Category] = 1}}
$p.categories = $CategorySummary

if ($p.Count -gt 0) {return $p}
return $null}

$varExprs = $ast.FindAll({param($node) $node -is [System.Management.Automation.Language.VariableExpressionAst]}, $true)
foreach ($v in $varExprs) {[void]$allVariables.Add(@{path = $v.VariablePath.ToString()
isSplatted = [bool]$v.Splatted})}
$typeLiterals = [System.Collections.ArrayList]::new()

foreach ($t in $ast.FindAll({param($n)
$n -is [System.Management.Automation.Language.TypeExpressionAst] -or
$n -is [System.Management.Automation.Language.TypeConstraintAst]}, $true)) {[void]$typeLiterals.Add($t.TypeName.FullName)}

$hasStopParsing = $false

foreach ($tok in $tokens) {$norm = $tok.Text -replace '[\u2013\u2014\u2015]','-' -replace '[`''""\u2018-\u201f]',''

if ($norm -eq '--%') {$hasStopParsing = $true; break}}

$statements = [System.Collections.ArrayList]::new()
$script:hasBg = $false

foreach ($p in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.PipelineBaseAst]}, $true)) {if ($p.PSObject.Properties['Background'] -and $p.Background) {$script:hasBg = $true; break}}


function Process-BlockStatements {param($Block)
if (-not $Block) {return}

foreach ($stmt in $Block.Statements) {$statement = @{type = $stmt.GetType().Name
text = $stmt.Extent.Text}

if ($stmt -is [System.Management.Automation.Language.PipelineAst]) {$elements = [System.Collections.ArrayList]::new()

foreach ($element in $stmt.PipelineElements) {$elemData = @{
type = $element.GetType().Name
text = $element.Extent.Text}

if ($element -is [System.Management.Automation.Language.CommandAst]) {$elemData.commandElements = @(Get-RawCommandElements -CmdAst $element)
$elemData.redirections = @(Get-RawRedirections -Redirections $element.Redirections)}

elseif ($element -is [System.Management.Automation.Language.CommandExpressionAst]) {$elemData.expressionType = $element.Expression.GetType().Name
$elemData.redirections = @(Get-RawRedirections -Redirections $element.Redirections)}
[void]$elements.Add($elemData)}
$statement.elements = @($elements)

$allNestedCmds = $stmt.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]},
$true)
$nestedCmds = [System.Collections.ArrayList]::new()

foreach ($cmd in $allNestedCmds) {if ($cmd.Parent -eq $stmt) {continue}

$nested = @{type = $cmd.GetType().Name
text = $cmd.Extent.Text
commandElements = @(Get-RawCommandElements -CmdAst $cmd)
redirections = @(Get-RawRedirections -Redirections $cmd.Redirections)}
[void]$nestedCmds.Add($nested)}

if ($nestedCmds.Count -gt 0) {$statement.nestedCommands = @($nestedCmds)}
$r = $stmt.FindAll({param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst]}, $true)

if ($r.Count -gt 0) {$rr = @(Get-RawRedirections -Redirections $r)
$statement.redirections = if ($statement.redirections) {@($statement.redirections) + $rr} else {$rr}}}

else {$nestedCmdAsts = $stmt.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]}, $true)
$nested = [System.Collections.ArrayList]::new()

foreach ($cmd in $nestedCmdAsts) {[void]$nested.Add(@{
type = 'CommandAst'
text = $cmd.Extent.Text
commandElements = @(Get-RawCommandElements -CmdAst $cmd)
redirections = @(Get-RawRedirections -Redirections $cmd.Redirections)})}

if ($nested.Count -gt 0) {$statement.nestedCommands = @($nested)}

$r = $stmt.FindAll({param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst]}, $true)

if ($r.Count -gt 0) {$statement.redirections = @(Get-RawRedirections -Redirections $r)}}

$sp = Get-SecurityPatterns $stmt

if ($sp) {$statement.securityPatterns = $sp}

[void]$statements.Add($statement)}


if ($Block.Traps) {foreach ($trap in $Block.Traps) {$statement = @{type = 'TrapStatementAst'
text = $trap.Extent.Text}

$nestedCmdAsts = $trap.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]}, $true)
$nestedCmds = [System.Collections.ArrayList]::new()

foreach ($cmd in $nestedCmdAsts) {$nested = @{type = $cmd.GetType().Name
text = $cmd.Extent.Text
commandElements = @(Get-RawCommandElements -CmdAst $cmd)
redirections = @(Get-RawRedirections -Redirections $cmd.Redirections)}
[void]$nestedCmds.Add($nested)}

if ($nestedCmds.Count -gt 0) {$statement.nestedCommands = @($nestedCmds)}

$r = $trap.FindAll({param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst]}, $true)

if ($r.Count -gt 0) {$statement.redirections = @(Get-RawRedirections -Redirections $r)}

$sp = Get-SecurityPatterns $trap

if ($sp) {$statement.securityPatterns = $sp}
[void]$statements.Add($statement)}}}

Process-BlockStatements -Block $ast.BeginBlock
Process-BlockStatements -Block $ast.ProcessBlock
Process-BlockStatements -Block $ast.EndBlock
Process-BlockStatements -Block $ast.CleanBlock
Process-BlockStatements -Block $ast.DynamicParamBlock

if ($ast.ParamBlock) {$pb = $ast.ParamBlock

$pn = [System.Collections.ArrayList]::new()

foreach ($c in $pb.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]}, $true)) {[void]$pn.Add(@{type='CommandAst';text=$c.Extent.Text;commandElements=@(Get-RawCommandElements -CmdAst $c);redirections=@(Get-RawRedirections -Redirections $c.Redirections)})}

$pr = $pb.FindAll({param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst]}, $true)
$ps = Get-SecurityPatterns $pb

if ($pn.Count -gt 0 -or $pr.Count -gt 0 -or $ps) {$st = @{type='ParamBlockAst';text=$pb.Extent.Text}

if ($pn.Count -gt 0) {$st.nestedCommands = @($pn)}

if ($pr.Count -gt 0) {$st.redirections = @(Get-RawRedirections -Redirections $pr)}

if ($ps) {$st.securityPatterns = $ps}

[void]$statements.Add($st)}}

$hasUsingStatements = $ast.UsingStatements -and $ast.UsingStatements.Count -gt 0
$hasScriptRequirements = $ast.ScriptRequirements -ne $null

$overallRisk = 0
foreach ($statement in $statements) {if ($statement.securityPatterns -and $statement.securityPatterns.riskScore -gt $overallRisk) {$overallRisk = $statement.securityPatterns.riskScore}}

Write-Host ""
Write-Host -f yellow ("-" * 100)
Write-Host -f yellow "`t`tEncoded PowerShell Command Analysis:"
Write-Host -f yellow ("-" * 100)
Write-Host -f cyan "Decoded Command:`n"
Write-Host -f gray "$Command`n"
Write-Host -f yellow ("-" * 100)
if ($overallRisk -gt 0) {$allFindings = @()

foreach ($statement in $statements) {if ($statement.securityPatterns.riskFindings) {Write-Host -f cyan "Indicators:`n"
$allFindings += $statement.securityPatterns.riskFindings}}

$allFindings | Sort-Object { [int]$_.Score } -Descending | ForEach-Object {Write-Host ("  +{0,-3}  {1}" -f $_.Score, $_.Indicator)}
Write-Host ""
Write-Host -f yellow ("-" * 100)

Write-Host -f cyan "Categories:`n"
$CategorySummary = @{}
foreach ($finding in $allFindings) {$Category = if ($script:IndicatorCategories.ContainsKey($finding.Indicator)) {$script:IndicatorCategories[$finding.Indicator]}

else {'Other'}

if ($CategorySummary.ContainsKey($Category)) {$CategorySummary[$Category]++}

else {$CategorySummary[$Category] = 1}}

foreach ($Item in ($CategorySummary.GetEnumerator() | Sort-Object Value -Descending)) {Write-Host ("  {0,-20} {1}" -f $Item.Name, $Item.Value)}

Write-Host ""
Write-Host -f yellow ("-" * 100)}
switch ($overallRisk) {{$_ -ge 75} {Write-Host -f red "Risk Score: $overallRisk (HIGH)`n"}
{$_ -ge 40 -and $_ -lt 75} {Write-Host -f yellow "Risk Score: $overallRisk (MEDIUM)`n"}
default {Write-Host -f green "Risk Score: $overallRisk (LOW)`n"}}

$output = @{valid = ($parseErrors.Count -eq 0)
errors = @($parseErrors | ForEach-Object {@{message = $_.Message
errorId = $_.ErrorId}})
statements = @($statements)
variables = @($allVariables)
hasStopParsing = $hasStopParsing
originalCommand = $Command
typeLiterals = @($typeLiterals)
hasUsingStatements = [bool]$hasUsingStatements
hasScriptRequirements = [bool]$hasScriptRequirements
hasBackgroundJob = [bool]$script:hasBg}
$output | Add-Member -NotePropertyName analysisTime -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')

if ($file) {$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$json = $output | ConvertTo-Json -Depth 10
$outFile = ".\analysis_$timestamp.json"
$json = $json -replace ' +', ' ' -replace '\[\s*\r?\n?', '[' -replace '\s*\r?\n?\]', ']' -replace '{\s*\r?\n?', '{' -replace '\s*\r?\n?}', '}' -replace '(?m)^ +', '' -replace '(\w"?),\s*\r?\n?"', '$1, "' -replace 'false, "', "false,`r`n`"" -replace 'true, "', "true,`r`n`""
$json | Set-Content -Path $outFile -Encoding UTF8
Write-Host -f cyan "Saved: $outFile`n"}}

sal evaluatescript enumerateencoding

Export-ModuleMember -Function enumerateencoding
Export-ModuleMember -Alias evaluatescript