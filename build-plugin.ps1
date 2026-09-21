param([string]$TechnitiumPath = "C:\Program Files\Technitium\DNS Server")
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$PublishDir = Join-Path $Here "bin\Release\publish"
$DistDir = Join-Path $Here "dist"
$Zip = Join-Path $DistDir "RemotePolicyBlockingApp.zip"

Push-Location $Here
try {
    if (Test-Path $PublishDir) { Remove-Item -Recurse -Force $PublishDir }

    dotnet publish -c Release `
        -p:TechnitiumDnsServerPath="$TechnitiumPath" `
        -p:GenerateDependencyFile=true `
        -o "$PublishDir"

    $Required = @(
        (Join-Path $PublishDir "RemotePolicyBlockingApp.dll"),
        (Join-Path $PublishDir "RemotePolicyBlockingApp.deps.json"),
        (Join-Path $PublishDir "dnsApp.config"),
        (Join-Path $PublishDir "README.md")
    )

    foreach ($File in $Required) {
        if (-not (Test-Path $File)) {
            throw "Required plugin package file was not produced: $File"
        }
    }

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    if (Test-Path $Zip) { Remove-Item $Zip }

    Compress-Archive -Path $Required -DestinationPath $Zip

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $Names = @($Archive.Entries | ForEach-Object { $_.FullName })
        if ($Names -notcontains "RemotePolicyBlockingApp.deps.json") {
            throw "Package validation failed: RemotePolicyBlockingApp.deps.json is absent."
        }
    }
    finally {
        $Archive.Dispose()
    }

    Write-Host "Created: $Zip"
    Write-Host "Validated: RemotePolicyBlockingApp.deps.json is present at ZIP root."
}
finally {
    Pop-Location
}
