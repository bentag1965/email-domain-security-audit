<#
.SYNOPSIS
    Audits public email-domain security records.

.DESCRIPTION
    Performs passive DNS queries for SPF, DMARC, DKIM selectors, MX, A, and AAAA
    records. Produces structured findings with severity, evidence, and guidance.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter()]
    [string[]]$DkimSelectors = @("selector1","selector2","google","default","s1","s2"),

    [Parameter()]
    [string]$OutputJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-DnsSafe {
    param([string]$Name,[string]$Type)
    try { @(Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop) }
    catch { @() }
}

function New-Finding {
    param([string]$Control,[string]$Severity,[string]$Title,[string]$Evidence,[string]$Recommendation)
    [pscustomobject]@{
        Control=$Control; Severity=$Severity; Title=$Title; Evidence=$Evidence; Recommendation=$Recommendation
    }
}

$domain = $Domain.Trim().TrimEnd(".").ToLowerInvariant()
$findings = @()
Write-Host "Auditing $domain..." -ForegroundColor Cyan

# SPF
$rootTxt = Resolve-DnsSafe -Name $domain -Type TXT
$txtValues = @($rootTxt | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join "" })
$spfRecords = @($txtValues | Where-Object { $_ -match "^v=spf1\b" })

if ($spfRecords.Count -eq 0) {
    $findings += New-Finding "SPF" "High" "SPF record not found" "" "Publish a single SPF record authorizing legitimate outbound senders."
} elseif ($spfRecords.Count -gt 1) {
    $findings += New-Finding "SPF" "High" "Multiple SPF records found" ($spfRecords -join " | ") "Consolidate SPF into one v=spf1 record."
} else {
    $spf = $spfRecords[0]
    if ($spf -match "(^|\s)\+all(\s|$)") {
        $findings += New-Finding "SPF" "Critical" "SPF permits all senders" $spf "Replace +all with a restrictive policy after validating authorized senders."
    } elseif ($spf -match "(^|\s)\?all(\s|$)") {
        $findings += New-Finding "SPF" "High" "SPF ends with neutral policy" $spf "Review senders and move toward -all where appropriate."
    } elseif ($spf -match "(^|\s)~all(\s|$)") {
        $findings += New-Finding "SPF" "Medium" "SPF uses soft fail" $spf "Validate legitimate senders and consider -all when ready."
    } elseif ($spf -match "(^|\s)-all(\s|$)") {
        $findings += New-Finding "SPF" "Info" "SPF uses hard fail" $spf "Continue monitoring authorized senders and DNS lookup count."
    } else {
        $findings += New-Finding "SPF" "Medium" "SPF record found without clear all mechanism" $spf "Review the SPF terminal policy."
    }
}

# DMARC
$dmarcName = "_dmarc.$domain"
$dmarcValues = @(Resolve-DnsSafe -Name $dmarcName -Type TXT | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join "" } | Where-Object { $_ -match "^v=DMARC1\b" })
if ($dmarcValues.Count -eq 0) {
    $findings += New-Finding "DMARC" "High" "DMARC record not found" "" "Publish DMARC with reporting, then progress toward enforcement."
} else {
    $dmarc = $dmarcValues[0]
    if ($dmarc -match "(?i)(^|;)\s*p=reject\s*(;|$)") {
        $findings += New-Finding "DMARC" "Info" "DMARC reject policy published" $dmarc "Maintain sender inventory and alignment."
    } elseif ($dmarc -match "(?i)(^|;)\s*p=quarantine\s*(;|$)") {
        $findings += New-Finding "DMARC" "Medium" "DMARC quarantine policy published" $dmarc "Review reports and progress toward reject when ready."
    } elseif ($dmarc -match "(?i)(^|;)\s*p=none\s*(;|$)") {
        $findings += New-Finding "DMARC" "High" "DMARC is monitoring-only" $dmarc "Validate legitimate senders, then move toward quarantine or reject."
    } else {
        $findings += New-Finding "DMARC" "High" "DMARC policy could not be classified" $dmarc "Review DMARC syntax and confirm a valid p= policy."
    }
    if ($dmarc -notmatch "(?i)(^|;)\s*rua=") {
        $findings += New-Finding "DMARC" "Low" "No aggregate reporting address found" $dmarc "Consider adding rua reporting."
    }
}

# DKIM candidates
$resolvedSelectors = @()
foreach ($selector in $DkimSelectors) {
    if ([string]::IsNullOrWhiteSpace($selector)) { continue }
    $name = "$selector._domainkey.$domain"
    $values = @(Resolve-DnsSafe -Name $name -Type TXT | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join "" })
    if ($values.Count -gt 0) { $resolvedSelectors += "$selector => $($values -join ' | ')" }
}
if ($resolvedSelectors.Count -gt 0) {
    $findings += New-Finding "DKIM" "Info" "Candidate DKIM selectors resolved" ($resolvedSelectors -join " || ") "Confirm active senders sign and align with the visible From domain."
} else {
    $findings += New-Finding "DKIM" "Low" "No candidate DKIM selectors resolved" ("Tested: " + ($DkimSelectors -join ", ")) "Identify selectors from a signed message or sending platform; this result is inconclusive."
}

# MX
$mx = Resolve-DnsSafe -Name $domain -Type MX
if ($mx.Count -eq 0) {
    $findings += New-Finding "MX" "Medium" "MX records not found" "" "Confirm whether the domain is intended to receive mail."
} else {
    $mxEvidence = @($mx | ForEach-Object { "$($_.Preference) $($_.NameExchange)" }) -join " | "
    $findings += New-Finding "MX" "Info" "MX records found" $mxEvidence "Review providers and remove obsolete MX records."
}

# Address records
$a = Resolve-DnsSafe -Name $domain -Type A
$aaaa = Resolve-DnsSafe -Name $domain -Type AAAA
if ($a.Count -eq 0 -and $aaaa.Count -eq 0) {
    $findings += New-Finding "DNS" "Low" "No A or AAAA record found at root domain" "" "Confirm whether root address resolution is expected."
} else {
    $addresses = @($a | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }) + @($aaaa | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    $findings += New-Finding "DNS" "Info" "Address records resolved" ($addresses -join ", ") "Maintain DNS ownership and remove stale records."
}

$severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Info=4 }
$ordered = @($findings | Sort-Object { $severityOrder[$_.Severity] }, Control)

foreach ($finding in $ordered) {
    Write-Host ("[{0}] {1}: {2}" -f $finding.Severity.ToUpper(),$finding.Control,$finding.Title)
    if ($finding.Evidence) { Write-Host ("  Evidence: {0}" -f $finding.Evidence) }
    Write-Host ("  Recommendation: {0}" -f $finding.Recommendation)
    Write-Host ""
}

$report = [pscustomobject]@{
    Domain=$domain
    AuditedAt=(Get-Date).ToUniversalTime().ToString("o")
    Findings=$ordered
    Summary=[pscustomobject]@{
        Critical=@($ordered | Where-Object Severity -eq "Critical").Count
        High=@($ordered | Where-Object Severity -eq "High").Count
        Medium=@($ordered | Where-Object Severity -eq "Medium").Count
        Low=@($ordered | Where-Object Severity -eq "Low").Count
        Info=@($ordered | Where-Object Severity -eq "Info").Count
    }
}

if ($OutputJson) {
    $parent = Split-Path -Parent $OutputJson
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputJson -Encoding UTF8
    Write-Host "JSON report written to $OutputJson" -ForegroundColor Cyan
}

$report