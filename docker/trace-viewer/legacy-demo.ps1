<#
.SYNOPSIS
  Repeatable, guarded local demo of the AgentOps trace viewer against the existing,
  ledger-less ("legacy") PostgreSQL database.

.DESCRIPTION
  Windows PowerShell 5.1.  Actions:

    start   Start a temporary PostgreSQL container on the existing data volume and a
            viewer container that shares its network namespace.  Only
            127.0.0.1:8000 is published.  PostgreSQL's own port is never published.
    status  Read-only report on the demo resources.  Changes nothing.
    stop    Stop and remove ONLY the two demo containers and the private network.

  -Open     (start only) open http://127.0.0.1:8000/ in the default browser.

  Fixed resource identities:
    container  agentops-legacy-demo-pg
    container  agentops-legacy-demo-viewer
    network    agentops-legacy-demo-net
    label      agentops.demo=legacy-viewer

  What this script never does: start, stop, modify or remove the original
  agentops-postgres container; build images; run SQL or migrations; delete or prune
  volumes, images, backups or evidence files; publish PostgreSQL port 5432.

  SAFETY DETAIL - read this.  The PostgreSQL data volume is mounted READ-WRITE because
  PostgreSQL cannot start without that.  Starting and stopping PostgreSQL rewrites some
  of its own files (the postmaster PID file, a shutdown checkpoint, WAL position).  This
  demo therefore does NOT guarantee that the database files stay byte-for-byte unchanged.
  The script itself runs no SQL and the viewer role is read-only.  Take a backup first;
  the script refuses to start without one.

  NOT A SECURITY MODEL.  The demo relies on PostgreSQL's local "trust" rule for
  connections from 127.0.0.1 inside the shared network namespace, so any non-empty
  password value is accepted.  The API has no authentication.  The password value used
  here is generated at random for each start, handed to Docker through the process
  environment, and never printed or stored.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet('start', 'status', 'stop')]
  [string]$Action,

  [switch]$Open
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Fixed identities and constants
# ---------------------------------------------------------------------------
$PgName          = 'agentops-legacy-demo-pg'
$ViewerName      = 'agentops-legacy-demo-viewer'
$NetworkName     = 'agentops-legacy-demo-net'
$LabelKey        = 'agentops.demo'
$LabelValue      = 'legacy-viewer'
$LabelFilter     = 'label=agentops.demo=legacy-viewer'
$OriginalName    = 'agentops-postgres'
$VolumeName      = 'agentops_postgres-data'
$ViewerImage     = 'agentops-trace-viewer:local'
$DataDir         = '/var/lib/postgresql/data'
$PublishMapping  = '127.0.0.1:8000:8000'     # the ONLY published mapping
$HostPort        = 8000
$Url             = 'http://127.0.0.1:8000/'
$BackupRoot      = Join-Path $env:LOCALAPPDATA 'agentops-backups'
$PgReadyTries    = 30     # x 2 s
$ViewerReadyTries = 20    # x 1 s
$PgStopSeconds   = 30
$ViewerStopSeconds = 10

# Containers and networks this invocation created (used for failure cleanup only).
$script:Created = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Say([string]$Message) { Write-Host $Message }

function Fail([string]$Message) { throw $Message }

# Runs docker, returns Code and Out (stdout+stderr lines).  Never throws on a
# non-zero exit; callers decide.
function Invoke-Docker {
  param([string[]]$DockerArgs)
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $lines = & docker @DockerArgs 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $old
  }
  return [pscustomobject]@{ Code = $code; Out = @($lines) }
}

function Docker-Ok {
  param([string[]]$DockerArgs)
  $r = Invoke-Docker $DockerArgs
  if ($r.Code -ne 0) {
    Fail ("docker " + ($DockerArgs[0..([Math]::Min(1, $DockerArgs.Count - 1))] -join ' ') + " failed (exit " + $r.Code + ")")
  }
  return $r.Out
}

function Host-Listening([int]$Port) {
  $hits = @(netstat -ano | Select-String 'LISTENING' | Select-String (':' + $Port + '\s'))
  return ($hits.Count -gt 0)
}

function Container-Exists([string]$Name) {
  $names = @(Docker-Ok @('ps', '-a', '--format', '{{.Names}}'))
  return ($names -contains $Name)
}

function Network-Exists([string]$Name) {
  $names = @(Docker-Ok @('network', 'ls', '--format', '{{.Name}}'))
  return ($names -contains $Name)
}

function Container-Field([string]$Name, [string]$Template) {
  $r = Invoke-Docker @('inspect', $Name, '--format', $Template)
  if ($r.Code -ne 0) { return $null }
  return (($r.Out -join "`n").Trim())
}

# True only when the container carries exactly our label value.
function Container-Owned([string]$Name) {
  $json = Container-Field $Name '{{json .Config.Labels}}'
  if (-not $json) { return $false }
  if ($json -eq 'null') { return $false }
  $labels = $json | ConvertFrom-Json
  $prop = $labels.PSObject.Properties[$LabelKey]
  return (($null -ne $prop) -and ($prop.Value -eq $LabelValue))
}

function Network-Owned([string]$Name) {
  $r = Invoke-Docker @('network', 'inspect', $Name, '--format', '{{json .Labels}}')
  if ($r.Code -ne 0) { return $false }
  $json = ($r.Out -join "`n").Trim()
  if (-not $json -or $json -eq 'null') { return $false }
  $labels = $json | ConvertFrom-Json
  $prop = $labels.PSObject.Properties[$LabelKey]
  return (($null -ne $prop) -and ($prop.Value -eq $LabelValue))
}

function Demo-Resources {
  $containers = @()
  foreach ($n in @(Docker-Ok @('ps', '-a', '--format', '{{.Names}}'))) {
    if ($n -eq $PgName -or $n -eq $ViewerName) { $containers += $n }
  }
  foreach ($n in @(Docker-Ok @('ps', '-a', '--filter', $LabelFilter, '--format', '{{.Names}}'))) {
    if ($containers -notcontains $n) { $containers += $n }
  }
  $networks = @()
  foreach ($n in @(Docker-Ok @('network', 'ls', '--format', '{{.Name}}'))) {
    if ($n -eq $NetworkName) { $networks += $n }
  }
  foreach ($n in @(Docker-Ok @('network', 'ls', '--filter', $LabelFilter, '--format', '{{.Name}}'))) {
    if ($networks -notcontains $n) { $networks += $n }
  }
  return [pscustomobject]@{ Containers = $containers; Networks = $networks }
}

# Any container other than the demo pair that uses the demo network or shares the
# demo PostgreSQL container's namespace.
function Unrelated-Dependents {
  $ids = @(Docker-Ok @('ps', '-a', '-q'))
  if ($ids.Count -eq 0) { return @() }
  $pgId = Container-Field $PgName '{{.Id}}'
  $found = @()
  $rows = @(Docker-Ok (@('inspect') + $ids + @('--format', '{{.Name}} {{.HostConfig.NetworkMode}}')))
  foreach ($row in $rows) {
    $parts = $row.Trim().Split(' ')
    $name = $parts[0].TrimStart('/')
    $mode = ''
    if ($parts.Count -gt 1) { $mode = $parts[1] }
    if ($name -eq $PgName -or $name -eq $ViewerName) { continue }
    $sharesPg = ($pgId -and $mode -eq ('container:' + $pgId))
    if ($mode -eq $NetworkName -or $sharesPg) { $found += $name }
  }
  return $found
}

function Wait-Pg {
  for ($i = 1; $i -le $PgReadyTries; $i++) {
    Start-Sleep -Seconds 2
    $state = Container-Field $PgName '{{.State.Status}}'
    if ($state -ne 'running') { Fail "PostgreSQL container is '$state', not running" }
    $r = Invoke-Docker @('exec', $PgName, 'pg_isready', '-U', 'agentops', '-d', 'agentops')
    if ($r.Code -eq 0) { return }
  }
  Fail "PostgreSQL was not ready within $($PgReadyTries * 2) seconds"
}

function Get-Url([string]$Path) {
  try {
    $r = Invoke-WebRequest -Uri ($Url.TrimEnd('/') + $Path) -UseBasicParsing -TimeoutSec 10
    return [pscustomobject]@{ Code = [int]$r.StatusCode; Body = $r.Content }
  } catch {
    $resp = $null
    if ($_.Exception -is [System.Net.WebException]) { $resp = $_.Exception.Response }
    if ($resp) { return [pscustomobject]@{ Code = [int]$resp.StatusCode; Body = '' } }
    return [pscustomobject]@{ Code = 0; Body = '' }
  }
}

function Wait-Viewer {
  for ($i = 1; $i -le $ViewerReadyTries; $i++) {
    Start-Sleep -Seconds 1
    if ((Container-Field $ViewerName '{{.State.Status}}') -ne 'running') {
      Fail 'viewer container stopped unexpectedly'
    }
    if ((Get-Url '/api/health').Code -eq 200) { return }
  }
  Fail "viewer was not healthy within $ViewerReadyTries seconds"
}

# Removes one container this script owns: exact name AND matching label, else refuses.
function Remove-OwnedContainer([string]$Name, [int]$StopSeconds) {
  if (-not (Container-Exists $Name)) { return }
  if (-not (Container-Owned $Name)) {
    Fail "refusing to remove '$Name': it does not carry the label $LabelKey=$LabelValue"
  }
  $null = Invoke-Docker @('stop', '-t', "$StopSeconds", $Name)
  $r = Invoke-Docker @('rm', $Name)
  if ($r.Code -ne 0) { Fail "could not remove container '$Name'" }
  Say "removed container $Name"
}

function Remove-OwnedNetwork([string]$Name) {
  if (-not (Network-Exists $Name)) { return }
  if (-not (Network-Owned $Name)) {
    Fail "refusing to remove network '$Name': it does not carry the label $LabelKey=$LabelValue"
  }
  $r = Invoke-Docker @('network', 'rm', $Name)
  if ($r.Code -ne 0) { Fail "could not remove network '$Name'" }
  Say "removed network $Name"
}

# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------
function Preflight {
  $r = Invoke-Docker @('version', '--format', '{{.Server.Version}}')
  if ($r.Code -ne 0) { Fail 'Docker is not available' }
  Say ("docker server: " + ($r.Out -join ''))

  $found = Demo-Resources
  if (@($found.Containers).Count -gt 0 -or @($found.Networks).Count -gt 0) {
    Fail ("demo resources already exist: " + ((@($found.Containers) + @($found.Networks)) -join ', ') +
          ". Run 'stop' first; nothing was changed.")
  }

  if (-not (Container-Exists $OriginalName)) { Fail "original container '$OriginalName' does not exist" }
  $state = Container-Field $OriginalName '{{.State.Status}}'
  if ($state -ne 'exited') { Fail "original container '$OriginalName' is '$state'; it must be stopped (exited)" }

  $volCheck = Invoke-Docker @('volume', 'inspect', $VolumeName, '--format', '{{.Name}}')
  if ($volCheck.Code -ne 0) { Fail "volume '$VolumeName' does not exist" }
  $mounts = Container-Field $OriginalName '{{range .Mounts}}{{.Name}} {{end}}'
  if (($mounts -split '\s+') -notcontains $VolumeName) { Fail "original container does not mount '$VolumeName'" }

  $users = @(Docker-Ok @('ps', '--filter', ('volume=' + $VolumeName), '--format', '{{.Names}}'))
  if ($users.Count -gt 0) { Fail ("running container(s) use the database volume: " + ($users -join ', ')) }

  $script:ImageId = Container-Field $OriginalName '{{.Image}}'
  if ($script:ImageId -notmatch '^sha256:[0-9a-f]{64}$') { Fail 'could not read the original PostgreSQL image id' }
  $imgCheck = Invoke-Docker @('image', 'inspect', $script:ImageId, '--format', '{{.Id}}')
  if ($imgCheck.Code -ne 0) { Fail 'the original PostgreSQL image is not available locally' }

  $viewerCheck = Invoke-Docker @('image', 'inspect', $ViewerImage, '--format', '{{.Id}}')
  if ($viewerCheck.Code -ne 0) {
    Fail "image '$ViewerImage' not found; build it first (this script never builds): docker build -f docker/trace-viewer/Dockerfile -t $ViewerImage ."
  }

  $backup = $null
  if (Test-Path -LiteralPath $BackupRoot) {
    $backup = Get-ChildItem -LiteralPath $BackupRoot -Recurse -File -Filter '*.dump' -ErrorAction SilentlyContinue |
      Where-Object { $_.Length -gt 0 } | Select-Object -First 1
  }
  if (-not $backup) { Fail "no non-empty database backup (*.dump) found under $BackupRoot; take one first" }
  Say ("backup found: " + $backup.FullName + " (" + $backup.Length + " bytes)")

  if (Host-Listening $HostPort) { Fail "host port $HostPort is already in use" }
  if (Host-Listening 5432) { Fail 'a host listener already exists on port 5432; refusing to start' }

  $os = Get-CimInstance Win32_OperatingSystem
  Say ("RAM free: {0:N2} GiB of {1:N2} GiB" -f ($os.FreePhysicalMemory / 1MB), ($os.TotalVisibleMemorySize / 1MB))
  Add-Type -AssemblyName System.Windows.Forms
  Say ("AC power: " + [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus)
}

function Assert-PortsFailClosed {
  $ports = @(Docker-Ok @('port', $PgName))
  $expected = '8000/tcp -> 127.0.0.1:8000'
  if ($ports.Count -ne 1 -or $ports[0].Trim() -ne $expected) {
    Fail ("unexpected published ports: " + ($ports -join ' | '))
  }
  $json = Container-Field $PgName '{{json .HostConfig.PortBindings}}'
  $bindings = $json | ConvertFrom-Json
  $keys = @($bindings.PSObject.Properties | ForEach-Object { $_.Name })
  if ($keys.Count -ne 1 -or $keys[0] -ne '8000/tcp') { Fail "unexpected port bindings: $json" }
  $b = @($bindings.'8000/tcp')
  if ($b.Count -ne 1 -or $b[0].HostIp -ne '127.0.0.1' -or $b[0].HostPort -ne '8000') {
    Fail "port 8000 is not bound to 127.0.0.1 only: $json"
  }
  $viewerPorts = @(Docker-Ok @('port', $ViewerName))
  if ($viewerPorts.Count -gt 0) { Fail 'the viewer container must not publish any port' }
  if (Host-Listening 5432) { Fail 'a host listener exists on port 5432' }
  Say 'port guard OK: only 127.0.0.1:8000 is published; nothing listens on host port 5432'
}

function Verify-Api {
  $health = Get-Url '/api/health'
  Say ("GET /api/health            -> " + $health.Code)
  $failed = ($health.Code -ne 200)
  foreach ($p in @('/api/traces?limit=1', '/api/anomalies?limit=1')) {
    $r = Get-Url $p
    $total = ''
    if ($r.Code -eq 200) {
      try { $total = '  total=' + (($r.Body | ConvertFrom-Json).total) } catch { $total = '' }
    }
    Say (("GET {0,-24} -> {1}{2}" -f $p, $r.Code, $total))
    if ($r.Code -ne 200) { $failed = $true }
    if ($r.Code -eq 503) {
      Say '  503 usually means a missing grant or database error (a dbt run removes the analytics view grants).'
    }
  }
  $root = Get-Url '/'
  Say ("GET /                       -> " + $root.Code)
  if ($root.Code -ne 200) { $failed = $true }
  if ($failed) { Fail 'API verification failed' }
}

function Start-Demo {
  Preflight

  # Cleanup lives in ONE place, the finally block, so that it also runs when the
  # start is interrupted (Ctrl+C / pipeline stop), not only when a step throws.
  $succeeded = $false
  try {
    $env:TRACE_VIEWER_DB_PASSWORD = [guid]::NewGuid().ToString('N')
    $r = Invoke-Docker @('network', 'create', '--driver', 'bridge', '--label', ($LabelKey + '=' + $LabelValue), $NetworkName)
    if ($r.Code -ne 0) { Fail 'could not create the private network' }
    [void]$script:Created.Add(@('network', $NetworkName))
    Say "created network $NetworkName"

    $r = Invoke-Docker @('run', '-d', '--name', $PgName, '--network', $NetworkName, '--restart', 'no',
                         '--label', ($LabelKey + '=' + $LabelValue),
                         '-p', $PublishMapping,
                         '-v', ($VolumeName + ':' + $DataDir),
                         $script:ImageId)
    if ($r.Code -ne 0) { Fail 'could not start the PostgreSQL container' }
    [void]$script:Created.Add(@('container', $PgName))
    Say "started container $PgName"

    Wait-Pg
    $log = (Docker-Ok @('logs', $PgName)) -join "`n"
    if ($log -notmatch 'Skipping initialization') {
      Fail 'PostgreSQL did not report an existing database directory; refusing to continue'
    }
    Say 'PostgreSQL ready; existing data directory detected (initialization skipped)'

    # The password value reaches the container through the environment of this
    # process ("-e NAME" with no value); it is not part of any command line.
    $r = Invoke-Docker @('run', '-d', '--name', $ViewerName, '--network', ('container:' + $PgName), '--restart', 'no',
                         '--label', ($LabelKey + '=' + $LabelValue),
                         '--read-only', '--tmpfs', '/tmp', '--cap-drop', 'ALL',
                         '--security-opt', 'no-new-privileges:true',
                         '-e', 'TRACE_VIEWER_DB_HOST=127.0.0.1',
                         '-e', 'TRACE_VIEWER_DB_PORT=5432',
                         '-e', 'TRACE_VIEWER_DB_NAME=agentops',
                         '-e', 'TRACE_VIEWER_DB_USER=trace_viewer_reader',
                         '-e', 'TRACE_VIEWER_DB_PASSWORD',
                         $ViewerImage)
    if ($r.Code -ne 0) { Fail 'could not start the viewer container' }
    [void]$script:Created.Add(@('container', $ViewerName))
    Say "started container $ViewerName"

    Assert-PortsFailClosed
    Wait-Viewer
    Verify-Api
    $succeeded = $true
  } catch {
    Say ('start failed: ' + $_.Exception.Message)
    throw
  } finally {
    Remove-Item Env:\TRACE_VIEWER_DB_PASSWORD -ErrorAction SilentlyContinue
    if (-not $succeeded) {
      Say 'start did not complete; removing only the resources this invocation created'
      Cleanup-Created
    }
  }

  Say ''
  Say "Demo is running: $Url   (loopback only, no authentication)"
  Say 'Browser checklist:'
  Say '  1. Traces tab lists the traces; open one and expand the execution tree and span details.'
  Say '  2. Anomalies tab lists the anomalies with severity, service and time.'
  Say '  3. Open an anomaly: read the explanation, baseline and the RCA panel (confidence, limitations, ranked evidence).'
  Say '  4. Use "View related trace" and then Back to return to the anomaly.'
  Say "When finished, run: powershell -NoProfile -File docker/trace-viewer/legacy-demo.ps1 stop"
  Say "(if your execution policy blocks the script, add -ExecutionPolicy Bypass: it applies to that one process only)"
  if ($Open) { Start-Process $Url }
}

# Failure / interruption cleanup: only resources created by THIS invocation, in reverse
# order, each verified by exact name and label.  Never touches anything that pre-existed
# and never discovers resources by name or label on its own.
#
# Cleanup is best effort.  It runs for a failed step and for a Ctrl+C / pipeline stop
# (the finally block still executes).  It CANNOT be guaranteed for: the process being
# killed (Stop-Process, Task Manager, closing the terminal window), a power loss or
# system crash, Docker Desktop stopping mid-start, or a second interrupt while cleanup
# is running.  A container created in the instant between "docker run" returning and
# its registration below is also not known to this invocation.  In every such case run
# "status" and then "stop": stop removes only exact-name, labelled demo resources, and
# a new "start" refuses while any demo resource exists.
function Cleanup-Created {
  for ($i = $script:Created.Count - 1; $i -ge 0; $i--) {
    $kind = $script:Created[$i][0]
    $name = $script:Created[$i][1]
    try {
      if ($kind -eq 'container') { Remove-OwnedContainer $name $PgStopSeconds }
      else { Remove-OwnedNetwork $name }
    } catch {
      Say ("cleanup problem: " + $_.Exception.Message)
    }
  }
}

# ---------------------------------------------------------------------------
# status (read-only)
# ---------------------------------------------------------------------------
function Show-Status {
  $r = Invoke-Docker @('version', '--format', '{{.Server.Version}}')
  if ($r.Code -ne 0) { Fail 'Docker is not available' }

  $found = Demo-Resources
  foreach ($name in @($PgName, $ViewerName)) {
    if (@($found.Containers) -contains $name) {
      $state = Container-Field $name '{{.State.Status}}'
      $owned = Container-Owned $name
      $ports = (@(Docker-Ok @('port', $name)) -join '; ')
      if (-not $ports) { $ports = 'none published' }
      Say ("container {0}: {1}; labelled={2}; ports: {3}" -f $name, $state, $owned, $ports)
    } else {
      Say "container ${name}: not present"
    }
  }
  foreach ($name in @($found.Containers)) {
    if ($name -ne $PgName -and $name -ne $ViewerName) { Say "WARNING: other labelled container: $name" }
  }
  if (@($found.Networks) -contains $NetworkName) {
    $netInfo = Invoke-Docker @('network', 'inspect', $NetworkName, '--format', '{{json .Containers}}')
    $members = @()
    if ($netInfo.Code -eq 0) {
      $json = ($netInfo.Out -join "`n").Trim()
      if ($json -and $json -ne 'null') {
        $obj = $json | ConvertFrom-Json
        foreach ($p in $obj.PSObject.Properties) { $members += $p.Value.Name }
      }
    }
    Say ("network {0}: present; labelled={1}; attached: {2}" -f $NetworkName, (Network-Owned $NetworkName), ($members -join ', '))
  } else {
    Say "network ${NetworkName}: not present"
  }

  if ((Container-Exists $ViewerName) -and ((Container-Field $ViewerName '{{.State.Status}}') -eq 'running')) {
    Say ("viewer health: GET /api/health -> " + (Get-Url '/api/health').Code)
  } else {
    Say 'viewer health: viewer is not running'
  }
  if (Container-Exists $OriginalName) {
    Say ("original container {0}: {1}" -f $OriginalName, (Container-Field $OriginalName '{{.State.Status}}'))
  } else {
    Say "original container ${OriginalName}: not present"
  }
  $volOk = (Invoke-Docker @('volume', 'inspect', $VolumeName, '--format', '{{.Name}}')).Code -eq 0
  Say ("database volume {0}: {1}" -f $VolumeName, $(if ($volOk) { 'present' } else { 'MISSING' }))
  Say ("host port {0}: {1}; host port 5432: {2}" -f $HostPort, $(if (Host-Listening $HostPort) { 'listening' } else { 'free' }), $(if (Host-Listening 5432) { 'LISTENING' } else { 'free' }))
}

# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------
function Stop-Demo {
  $r = Invoke-Docker @('version', '--format', '{{.Server.Version}}')
  if ($r.Code -ne 0) { Fail 'Docker is not available' }

  $found = Demo-Resources
  $unknown = @($found.Containers | Where-Object { $_ -ne $PgName -and $_ -ne $ViewerName })
  if ($unknown.Count -gt 0) { Fail ("ownership is ambiguous: unexpected labelled container(s): " + ($unknown -join ', ')) }
  $unknownNets = @($found.Networks | Where-Object { $_ -ne $NetworkName })
  if ($unknownNets.Count -gt 0) { Fail ("ownership is ambiguous: unexpected labelled network(s): " + ($unknownNets -join ', ')) }

  if (@($found.Containers).Count -eq 0 -and @($found.Networks).Count -eq 0) {
    Say 'no demo resources present; nothing to stop'
  } else {
    foreach ($name in @($PgName, $ViewerName)) {
      if ((Container-Exists $name) -and -not (Container-Owned $name)) {
        Fail "ownership is ambiguous: '$name' exists without the label $LabelKey=$LabelValue; nothing was removed"
      }
    }
    if ((Network-Exists $NetworkName) -and -not (Network-Owned $NetworkName)) {
      Fail "ownership is ambiguous: network '$NetworkName' exists without the label; nothing was removed"
    }
    if (Container-Exists $PgName) {
      $dependents = @(Unrelated-Dependents)
      if ($dependents.Count -gt 0) {
        Fail ("an unrelated container depends on the demo: " + ($dependents -join ', ') + "; nothing was removed")
      }
    }
    if (Network-Exists $NetworkName) {
      $netInfo = Invoke-Docker @('network', 'inspect', $NetworkName, '--format', '{{json .Containers}}')
      if ($netInfo.Code -eq 0) {
        $json = ($netInfo.Out -join "`n").Trim()
        if ($json -and $json -ne 'null') {
          $obj = $json | ConvertFrom-Json
          foreach ($p in $obj.PSObject.Properties) {
            if ($p.Value.Name -ne $PgName) { Fail ("unrelated container attached to the demo network: " + $p.Value.Name) }
          }
        }
      }
    }

    # viewer first, then PostgreSQL (graceful, bounded), then the network
    Remove-OwnedContainer $ViewerName $ViewerStopSeconds
    Remove-OwnedContainer $PgName $PgStopSeconds
    Remove-OwnedNetwork $NetworkName
  }

  # Verification
  $after = Demo-Resources
  if (@($after.Containers).Count -gt 0 -or @($after.Networks).Count -gt 0) {
    Fail ("demo resources remain: " + ((@($after.Containers) + @($after.Networks)) -join ', '))
  }
  if (Host-Listening $HostPort) { Fail "host port $HostPort is still listening" }
  if (Container-Exists $OriginalName) {
    $state = Container-Field $OriginalName '{{.State.Status}}'
    if ($state -ne 'exited') { Fail "original container is '$state'" }
    Say "original container $OriginalName still stopped (exited)"
  }
  $vol = Invoke-Docker @('volume', 'inspect', $VolumeName, '--format', '{{.Name}}')
  if ($vol.Code -ne 0) { Fail "database volume '$VolumeName' is MISSING" }
  Say "database volume $VolumeName still present; images, backups and evidence files untouched"
  Say 'demo stopped: no demo resources remain; host port 8000 is free'
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
try {
  if ($Open -and $Action -ne 'start') { Fail '-Open is only valid with the start action' }
  switch ($Action) {
    'start'  { Start-Demo }
    'status' { Show-Status }
    'stop'   { Stop-Demo }
  }
  exit 0
} catch {
  Write-Host ("ERROR: " + $_.Exception.Message)
  exit 1
}
