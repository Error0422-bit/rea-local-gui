# REA Local GUI - Windows environment helper
# Checks dependencies. Optional Python package installation.
# Run from the repository directory.

param(
    [switch]$InstallPythonDeps,
    [switch]$CreateConfig
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

Write-Host ""
Write-Host "=================================="
Write-Host " REA Local GUI - Environment Check"
Write-Host "=================================="
Write-Host "Project: $root"
Write-Host ""

function Check-Tool {
    param([string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue

    if ($null -ne $command) {
        Write-Host "[OK] $Name"
        return $true
    }

    Write-Host "[MISSING] $Name"
    return $false
}

# Check project files
Write-Host "1. Checking project files"

$required = @(
    "analysis_core.py",
    "rea_gui.py",
    "full_decompile.py",
    "export_pseudocode.py",
    "report_v21.py",
    "requirements.txt",
    "config.example.json",
    "scripts\ExportFindings.java"
)

foreach ($name in $required) {
    $path = Join-Path $root $name

    if (Test-Path -LiteralPath $path) {
        Write-Host "[OK] $name"
    } else {
        Write-Warning "Missing project file: $name"
    }
}

Write-Host ""
Write-Host "2. Checking installed tools"

$hasPy = Check-Tool "py"
$hasPython = Check-Tool "python"

$null = Check-Tool "java"
$null = Check-Tool "dotnet"
$null = Check-Tool "node"
$null = Check-Tool "npm"
$null = Check-Tool "npx"
$hasIlspy = Check-Tool "ilspycmd"

if (-not $hasIlspy) {
    $ilspyPath = Join-Path $env:USERPROFILE ".dotnet\tools\ilspycmd.exe"

    if (Test-Path -LiteralPath $ilspyPath) {
        Write-Host "[OK] ILSpy found in .dotnet tools"
    }
}

$pythonExe = $null
$pythonArgs = @()

if ($hasPy) {
    $pythonExe = "py"
    $pythonArgs = @("-3")
} elseif ($hasPython) {
    $pythonExe = "python"
}

if ($null -ne $pythonExe) {
    Write-Host ""
    Write-Host "Python version:"
    & $pythonExe @pythonArgs --version

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Python could not be started."
        $pythonExe = $null
    }
}

Write-Host ""
Write-Host "3. Checking Ghidra configuration"

$configFile = Join-Path $root "config.json"
$configExample = Join-Path $root "config.example.json"

if ($CreateConfig -and -not (Test-Path -LiteralPath $configFile)) {
    if (Test-Path -LiteralPath $configExample) {
        Copy-Item -LiteralPath $configExample -Destination $configFile
        Write-Host "[OK] Created config.json from example"
    } else {
        Write-Warning "config.example.json not found"
    }
}

if (Test-Path -LiteralPath $configFile) {
    try {
        $config = Get-Content -LiteralPath $configFile -Raw |
            ConvertFrom-Json

        $ghidraHome = [string]$config.ghidra_home

        if ($ghidraHome -and (Test-Path -LiteralPath $ghidraHome)) {
            Write-Host "[OK] Ghidra path exists: $ghidraHome"
        } else {
            Write-Warning "Check ghidra_home in config.json"
        }
    } catch {
        Write-Warning "config.json is not valid JSON"
    }
} else {
    Write-Warning "config.json missing"
    Write-Host "Use -CreateConfig and edit ghidra_home"
}

if ($InstallPythonDeps) {
    Write-Host ""
    Write-Host "4. Installing Python dependencies"

    if ($null -eq $pythonExe) {
        Write-Warning "Python unavailable; cannot install packages"
    } else {
        & $pythonExe @pythonArgs -m pip install -r (
            Join-Path $root "requirements.txt"
        )

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Python dependency installation failed"
        }
    }
}

Write-Host ""
Write-Host "5. Checking REA analysis engines"

if ($null -ne $pythonExe) {
    & $pythonExe @pythonArgs (
        Join-Path $root "analysis_core.py"
    ) --check
} else {
    Write-Warning "Engine check skipped: Python missing"
}

Write-Host ""
Write-Host "Environment check finished."
Write-Host "This checks availability, not decompilation correctness."
Write-Host "Edit config.json if Ghidra is not detected."
Write-Host ""
