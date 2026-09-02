[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$ExePath,
  [string]$AppName,
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\BlockApp-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

if ($Arg1 -and -not $ExePath) { $ExePath = $Arg1 }
if (-not $ExePath -and $env:ARG1) { $ExePath = $env:ARG1 }
if (-not $ExePath -and $args.Count -gt 0) { $ExePath = $args[0] }
if ($ExePath) {
  $ExePath = [Environment]::ExpandEnvironmentVariables($ExePath.Trim('"'))
  try { $ExePath = (Resolve-Path -LiteralPath $ExePath).Path } catch { }
}

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){ Write-Verbose $line }}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Now-Timestamp {
  $tz=(Get-Date).ToString('zzz').Replace(':','')
  (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + $tz
}

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Block Application ==="

$ts = Now-Timestamp
$lines = @()

try {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
  if (-not $isAdmin) { throw "Administrator privileges are required." }

  if (-not $ExePath) { throw "ExePath is required (or pass -Arg1 <path>)" }
  if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) { throw "File not found: $ExePath" }

  if (-not $AppName) { $AppName = [IO.Path]::GetFileNameWithoutExtension($ExePath) }

  $RuleBase     = "BlockApp_" + ($AppName -replace '\s+','_')
  $RuleInbound  = $RuleBase + "_In"
  $RuleOutbound = $RuleBase + "_Out"

  Write-Log ("Blocking app {0} at {1}" -f $AppName,$ExePath) 'INFO'

  $created = 0
  $status = "ok"

  $UseNetSecurity = [bool](Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)

  if ($UseNetSecurity) {

      # Modern Windows - existing NetSecurity implementation

      $existingOut = Get-NetFirewallRule -DisplayName $RuleOutbound -ErrorAction SilentlyContinue

      if ($existingOut) {

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_exists'
              direction = 'outbound'
              display_name = $RuleOutbound
          } | ConvertTo-Json -Compress -Depth 4)

      } else {

          New-NetFirewallRule `
              -DisplayName $RuleOutbound `
              -Direction Outbound `
              -Program $ExePath `
              -Action Block `
              -Enabled True `
              -Profile Any `
              -Protocol Any | Out-Null

          $created++

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_created'
              direction = 'outbound'
              display_name = $RuleOutbound
              program = $ExePath
              rule_action = 'Block'
          } | ConvertTo-Json -Compress -Depth 4)
      }

      $existingIn = Get-NetFirewallRule -DisplayName $RuleInbound -ErrorAction SilentlyContinue

      if ($existingIn) {

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_exists'
              direction = 'inbound'
              display_name = $RuleInbound
          } | ConvertTo-Json -Compress -Depth 4)

      } else {

          New-NetFirewallRule `
              -DisplayName $RuleInbound `
              -Direction Inbound `
              -Program $ExePath `
              -Action Block `
              -Enabled True `
              -Profile Any `
              -Protocol Any | Out-Null

          $created++

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_created'
              direction = 'inbound'
              display_name = $RuleInbound
              program = $ExePath
              rule_action = 'Block'
          } | ConvertTo-Json -Compress -Depth 4)
      }

  }
  else {

      # Legacy Windows - Windows Firewall COM API

      $FirewallPolicy = New-Object -ComObject HNetCfg.FwPolicy2

      # OUTBOUND
      $existingOut = $null

      try {
          $existingOut = $FirewallPolicy.Rules.Item($RuleOutbound)
      }
      catch {
          $existingOut = $null
      }

      if ($existingOut) {

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_exists'
              direction = 'outbound'
              display_name = $RuleOutbound
          } | ConvertTo-Json -Compress -Depth 4)

      }
      else {

          $FirewallRule = New-Object -ComObject HNetCfg.FWRule

          $FirewallRule.Name = $RuleOutbound
          $FirewallRule.Description = "Block outbound traffic for $AppName"
          $FirewallRule.ApplicationName = $ExePath

          # NET_FW_RULE_DIRECTION_OUT
          $FirewallRule.Direction = 2

          # NET_FW_ACTION_BLOCK
          $FirewallRule.Action = 0

          # NET_FW_IP_PROTOCOL_ANY
          $FirewallRule.Protocol = 256

          $FirewallRule.Enabled = $true

          # NET_FW_PROFILE2_ALL
          $FirewallRule.Profiles = 2147483647

          $FirewallPolicy.Rules.Add($FirewallRule)

          $created++

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_created'
              direction = 'outbound'
              display_name = $RuleOutbound
              program = $ExePath
              rule_action = 'Block'
          } | ConvertTo-Json -Compress -Depth 4)
      }

      # INBOUND
      $existingIn = $null

      try {
          $existingIn = $FirewallPolicy.Rules.Item($RuleInbound)
      }
      catch {
          $existingIn = $null
      }

      if ($existingIn) {

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_exists'
              direction = 'inbound'
              display_name = $RuleInbound
          } | ConvertTo-Json -Compress -Depth 4)

      }
      else {

          $FirewallRule = New-Object -ComObject HNetCfg.FWRule

          $FirewallRule.Name = $RuleInbound
          $FirewallRule.Description = "Block inbound traffic for $AppName"
          $FirewallRule.ApplicationName = $ExePath

          # NET_FW_RULE_DIRECTION_IN
          $FirewallRule.Direction = 1

          # NET_FW_ACTION_BLOCK
          $FirewallRule.Action = 0

          # NET_FW_IP_PROTOCOL_ANY
          $FirewallRule.Protocol = 256

          $FirewallRule.Enabled = $true
          $FirewallRule.Profiles = 2147483647

          $FirewallPolicy.Rules.Add($FirewallRule)

          $created++

          $lines += ([pscustomobject]@{
              timestamp = $ts
              host = $HostName
              action = 'block_app'
              copilot_action = $true
              type = 'rule_created'
              direction = 'inbound'
              display_name = $RuleInbound
              program = $ExePath
              rule_action = 'Block'
          } | ConvertTo-Json -Compress -Depth 4)
      }
  }

  if ($created -gt 0) {
      $status = "app_blocked"
  }
  elseif ($existingIn -or $existingOut) {
      $status = "already_exists"
  }


  # Verify both rules
  $rulesToVerify = @($RuleOutbound, $RuleInbound)

  foreach ($rn in $rulesToVerify) {

      if ($UseNetSecurity) {

          $r = Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue
          $af = if ($r) {
              Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r
          }
          else {
              $null
          }

          $prog = if ($af) {
              ($af.Program | Select-Object -First 1)
          }
          else {
              $null
          }

          $enabled = if ($r) { [bool]$r.Enabled } else { $false }
          $directionValue = if ($r) { "$($r.Direction)" } else { $null }
          $actionValue = if ($r) { "$($r.Action)" } else { $null }
      }
      else {

          $r = $null

          try {
              $r = $FirewallPolicy.Rules.Item($rn)
          }
          catch {
              $r = $null
          }

          $prog = if ($r) {
              $r.ApplicationName
          }
          else {
              $null
          }

          $enabled = if ($r) {
              [bool]$r.Enabled
          }
          else {
              $false
          }

          $directionValue = if ($r) {
              if ($r.Direction -eq 1) {
                  "Inbound"
              }
              elseif ($r.Direction -eq 2) {
                  "Outbound"
              }
              else {
                  "$($r.Direction)"
              }
          }
          else {
              $null
          }

          $actionValue = if ($r) {
              if ($r.Action -eq 0) {
                  "Block"
              }
              elseif ($r.Action -eq 1) {
                  "Allow"
              }
              else {
                  "$($r.Action)"
              }
          }
          else {
              $null
          }
      }

      $lines += ([pscustomobject]@{
          timestamp = $ts
          host = $HostName
          action = 'block_app'
          copilot_action = $true
          type = 'verify_rule'
          display_name = $rn
          exists = [bool]$r
          enabled = $enabled
          direction = $directionValue
          rule_action = $actionValue
          program = $prog
          program_matches = if ($prog) {
              ($prog -eq $ExePath)
          }
          else {
              $false
          }
      } | ConvertTo-Json -Compress -Depth 4)
  }

  $summary = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'block_app'
    copilot_action = $true
    type           = 'summary'
    app_name       = $AppName
    exe_path       = $ExePath
    rule_inbound   = $RuleInbound
    rule_outbound  = $RuleOutbound
    status         = $status
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 5 )) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'block_app'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 4 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}

