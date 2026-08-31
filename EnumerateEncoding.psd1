@{RootModule = 'EnumerateEncoding.psm1'
ModuleVersion = '1.0'
GUID = '788ad626-e728-4b27-9dcf-11b6e12bf0ea'
Author = 'Craig Plath'
CompanyName = 'Plath Consulting Incorporated'
Copyright = '© Craig Plath. All rights reserved.'
Description = 'Decode Base64-encoded PowerShell commands and perform a static security-oriented analysis of the decoded command.'
PowerShellVersion = '5.1'
FunctionsToExport = @('EnumerateEncoding')
CmdletsToExport = @()
VariablesToExport = @()
AliasesToExport = @('evaluatescript')
FileList = @('EnumerateEncoding.psm1')

PrivateData = @{PSData = @{Tags = @('base64', 'cybersecurity', 'encoding', 'soc', 'powershell')
LicenseUri = 'https://github.com/Schvenn/flattenjson/RuleInventory/EnumerateEncoding/blob/main/LICENSE'
ProjectUri = 'https://github.com/Schvenn/flattenjson/RuleInventory/EnumerateEncoding'
ReleaseNotes = 'Initial release.'}}}
