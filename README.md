# EnumerateEncoding

`EnumerateEncoding` is a PowerShell command-analysis function that decodes Base64-encoded PowerShell commands and performs a static security-oriented analysis of the decoded command.

The function uses the PowerShell Abstract Syntax Tree (AST) parser to enumerate commands, command elements, variables, type literals, redirections, nested commands, and several potentially suspicious PowerShell behaviors.

It **does not execute the decoded command**.

## Features

- Decode Base64-encoded PowerShell commands.
- Supports:
  - UTF-8
  - Unicode / UTF-16LE
  - Automatic encoding detection
- Parse the decoded command with the native PowerShell AST parser.
- Detect PowerShell parsing errors.
- Enumerate:
  - Commands and command elements
  - Nested commands
  - Variables
  - Type literals
  - Redirections
  - Script blocks
  - Sub-expressions
  - Member invocations
  - Expandable strings
  - Background jobs
  - `--%` stop-parsing tokens
  - `using` statements
  - Script requirements
- Identify interesting PowerShell aliases commonly encountered in scripts.
- Detect encoded-command switches such as `-EncodedCommand`.
- Search for suspicious security-related indicators.
- Categorize indicators such as:
  - Defense Evasion
  - Download
  - Execution
  - Obfuscation
  - Reflection
  - Memory Injection
  - Lateral Movement
  - LOLBin
- Generate a heuristic risk score.
- Display findings and risk categories in the console.
- Optionally save the complete analysis as a timestamped JSON file.

## Syntax

```powershell
enumerateencoding <EncodedCommand> [-EncodingType <UTF8|Unicode|Auto>] [-file]
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `EncodedCommand` | `string` | Required | Base64-encoded PowerShell command to analyze. |
| `EncodingType` | `string` | `Auto` | Encoding used when decoding the Base64 data. Valid values are `UTF8`, `Unicode`, and `Auto`. |
| `file` | `switch` | Off | Saves the analysis results to a timestamped JSON file. |

## Usage

### Basic analysis

```powershell
enumerateencoding 'VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA'
```

The command is decoded and then analyzed without being executed.

PowerShell's `-EncodedCommand` convention normally uses Unicode/UTF-16LE, so `Unicode` is often the appropriate choice for Base64 obtained from PowerShell command lines, but you can explicitly state either UTF8 or Unicode.

It no encoding type is stated, the script will attempt to determine the appropriate method using heuristics.

### Save the analysis

```powershell
enumerateencoding '<Base64String>' -file
```

A file similar to the following is created in the current directory:

```text
.\analysis_20260830_204500.json
```
## Analysis

### AST parsing

After decoding, the command is parsed using:

```powershell
[System.Management.Automation.Language.Parser]::ParseInput()
```

This allows the function to inspect the command structurally instead of relying exclusively on regular-expression matching.

Parse errors are retained in the output and the `valid` property indicates whether the decoded command parsed successfully.

### Command enumeration

The function extracts command information from PowerShell `CommandAst` nodes, including:

- AST node type
- Original text
- String values where available
- Expression types
- Child argument information
- Redirections

Nested commands are separately identified where applicable.

### Variables

Variable expressions are enumerated with their PowerShell variable paths.

Each variable entry contains:

```json
{
"path": "$variable",
"isSplatted": false
}
```

### Type literals

PowerShell type expressions and type constraints are collected into the `typeLiterals` output property.

### PowerShell constructs

The analysis identifies several constructs that can be useful when investigating obfuscated or suspicious PowerShell:

- Member invocations
- Sub-expressions
- Array expressions
- Parenthesized expressions
- Expandable strings
- Script blocks
- Background jobs
- `--%` stop-parsing tokens
- `using` statements
- Script requirements

## Suspicious Indicators

The function maintains a list of security-relevant indicators, including examples such as:

```text
Invoke-Expression
Invoke-WebRequest
Invoke-RestMethod
Invoke-Command
Add-Type
FromBase64String
Assembly.Load
Assembly.LoadFrom
Reflection
VirtualAlloc
CreateThread
WriteProcessMemory
Invoke-WmiMethod
Regsvr32
Rundll32
Start-BitsTransfer
BitsAdmin
Net.WebClient
AMSIUtils
AmsiScanBuffer
```

The indicator list is intended as a **heuristic security signal**, not a malware verdict.

Legitimate administrative and automation scripts can contain many of these commands.

## Alias Detection

The function specifically checks for aliases that can make PowerShell command lines less immediately recognizable.

Detected aliases include:

| Alias | Resolves To |
|---|---|
| `cat` | `Get-Content` |
| `cp` | `Copy-Item` |
| `curl` | `Invoke-WebRequest` |
| `del` | `Remove-Item` |
| `gc` | `Get-Content` |
| `gci` | `Get-ChildItem` |
| `gi` | `Get-Item` |
| `gp` | `Get-ItemProperty` |
| `iex` | `Invoke-Expression` |
| `irm` | `Invoke-RestMethod` |
| `iwr` | `Invoke-WebRequest` |
| `ls` | `Get-ChildItem` |
| `mv` | `Move-Item` |
| `ni` | `New-Item` |
| `ri` | `Remove-Item` |
| `rm` | `Remove-Item` |
| `rv` | `Remove-Variable` |
| `sal` | `Set-Alias` |
| `set` | `Set-Variable` |
| `sv` | `Set-Variable` |
| `wget` | `Invoke-WebRequest` |

Alias usage contributes to the heuristic risk score.

## Risk Scoring

The function calculates a heuristic risk score for each analyzed statement.

### Base scoring

| Finding | Score |
|---|---:|
| Encoded command | +25 |
| Script block | +5 |
| Sub-expression | +5 |
| Member invocation | +5 |
| Each interesting alias | +5 |
| Most suspicious indicators | +5 |

Certain indicators receive higher scores:

| Indicator | Score |
|---|---:|
| `AmsiUtils` | +25 |
| `AmsiScanBuffer` | +25 |
| `VirtualAlloc` | +20 |
| `CreateThread` | +20 |
| `WriteProcessMemory` | +20 |
| `Invoke-Expression` | +15 |

The presence of suspicious indicators also contributes to the reported risk reasons and findings.

### Risk levels

The displayed overall risk level is:

| Score | Level |
|---:|---|
| 0–39 | LOW |
| 40–74 | MEDIUM |
| 75+ | HIGH |

The score is **not a probability of maliciousness** and should not be treated as one. It is a triage heuristic intended to highlight commands that deserve further investigation.

## Indicator Categories

Indicators are mapped into categories:

| Category | Examples |
|---|---|
| Defense Evasion | `AmsiUtils`, `AmsiScanBuffer`, `Add-MpPreference`, `Set-MpPreference` |
| Download | `Invoke-WebRequest`, `Invoke-RestMethod`, `DownloadString`, `DownloadFile`, `WebClient`, `BitsAdmin` |
| Execution | `Invoke-Expression`, `Invoke-Command`, `Add-Type` |
| Obfuscation | `FromBase64String`, `EncodedCommand` |
| Reflection | `Assembly.Load`, `Assembly.LoadFrom`, `Reflection` |
| Memory Injection | `VirtualAlloc`, `CreateThread`, `WriteProcessMemory`, Marshal APIs |
| Lateral Movement | `Invoke-WmiMethod` |
| LOLBin | `Regsvr32`, `Rundll32` |

Indicators not explicitly mapped to a category are reported as `Other`.

## Console Output

The normal console output includes:

1. The decoded command.
2. Suspicious indicators, when present.
3. Individual indicator scores.
4. Indicator categories.
5. Overall risk score and severity.

A typical analysis is presented in a format similar to:

```text
----------------------------------------------------------------------------------------------------
        Encoded PowerShell Command Analysis:
----------------------------------------------------------------------------------------------------
Decoded Command:

<decoded command>

----------------------------------------------------------------------------------------------------
Indicators:

  +25  amsiutils
  +15  invoke-expression
  +5   invoke-webrequest

----------------------------------------------------------------------------------------------------
Categories:

  Defense Evasion       1
  Execution             1
  Download              1

----------------------------------------------------------------------------------------------------
Risk Score: 45 (MEDIUM)
```

## JSON Output

When `-file` is specified, the analysis is written as JSON.

The output contains properties including:

```json
{
  "valid": true,
  "errors": [],
  "statements": [],
  "variables": [],
  "hasStopParsing": false,
  "originalCommand": "...",
  "typeLiterals": [],
  "hasUsingStatements": false,
  "hasScriptRequirements": false,
  "hasBackgroundJob": false,
  "analysisTime": "2026-08-30 20:45:00 -04:00"
}
```

Individual statements can contain additional information such as:

```text
type
text
elements
nestedCommands
redirections
securityPatterns
```

Security-pattern information can include:

```text
hasMemberInvocations
hasSubExpressions
hasExpandableStrings
hasScriptBlocks
aliasUsage
hasEncodedCommand
encodedCommandUsage
suspiciousIndicatorCount
suspiciousIndicators
riskScore
riskReasons
riskFindings
categories
```

## Security Model

`EnumerateEncoding` is designed for **static analysis and triage**.

The decoded command is parsed as data using PowerShell's parser. The function does not use `Invoke-Expression`, `Start-Process`, or another mechanism to execute the decoded payload.

This makes it suitable for examining encoded PowerShell obtained from sources such as:

- SIEM alerts
- EDR telemetry
- Process command lines
- Windows event logs
- Incident-response artifacts
- Threat-hunting results
- Malware-analysis workflows

## Limitations

The analysis is heuristic and should not be considered a complete malware-detection engine.

In particular:

- Suspicious indicators can occur in completely legitimate scripts.
- Absence of an indicator does not mean the command is safe.
- Obfuscation techniques can evade simple string indicators.
- Risk scores are additive heuristics rather than statistical probabilities.
- Automatic encoding detection is heuristic.
- The analysis operates on the decoded command and does not execute it to determine runtime behavior.
- A command can be syntactically valid while still being malicious.
- A command can be syntactically invalid while containing useful forensic indicators.

For incident response, the output should therefore be considered one input into a broader investigation.

## Requirements

The function relies on PowerShell's built-in language and parser APIs and does not require third-party PowerShell modules.

It uses classes under:

```text
System.Management.Automation.Language
System.Collections
System.Collections.Generic
System.Text
System
```

