#Requires -Version 4.0
<#
.SYNOPSIS
    Roblox Checker & Fixer by Rumi - Comprehensive Roblox diagnostic and repair tool
.DESCRIPTION
    Script untuk mendiagnosis dan memperbaiki masalah Roblox yang sering crash
    Mendukung semua versi Windows dengan safety measures dan secure by design
.NOTES
    Version: 2.0
    Author: Rumi
    Compatible: Windows 7/8/8.1/10/11 (x86/x64/ARM64)
    Full Support: Windows 10 Build 1507+ / Windows 11 All Builds
#>

param(
    [switch]$Debug,
    [switch]$NoCleanup,
    [string]$LogPath = "$env:TEMP\RobloxChecker"
)

# ==================== INITIALIZATION ====================
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Global Variables
$Global:ScriptVersion = "2.0.0"
$Global:ScriptName = "Roblox Checker by Rumi"
$Global:LogFile = ""
$Global:TempFiles = @()
$Global:ProcessesToCleanup = @()
$Global:SafetyBackups = @()

# Colors for UI
$Colors = @{
    Success = 'Yellow'      # Peach/Yellow
    Error = 'Red'
    Warning = 'DarkYellow'  # Orange/Gold
    Info = 'White'          # Cream/White
    Debug = 'Magenta'
    Header = 'Gray'         # Cream/Beige
    Accent = 'DarkYellow'   # Orange/Peach
}

# ==================== WINDOWS COMPATIBILITY CHECK ====================

function Test-WindowsCompatibility {
	# Debug: Show we're in Test-WindowsCompatibility
	if ($Global:IsElevatedProcess) {
		Write-Host "🔧 Test-WindowsCompatibility: Starting..." -ForegroundColor Yellow
	}
	
	$compatibility = @{
		OSVersion = $null
		OSBuild = $null
		Architecture = $null
		PowerShellVersion = $null
		IsWindows10 = $false
		IsWindows11 = $false
		IsARM64 = $false
		SupportsCIM = $false
		SupportsWMI = $false
		CompatibilityLevel = "Unknown"
	}
	
	try {
		# Debug: Show we're getting OS info
		if ($Global:IsElevatedProcess) {
			Write-Host "🔧 Test-WindowsCompatibility: Getting OS info..." -ForegroundColor Yellow
		}
		
		# Get OS info using CIM (preferred) with WMI fallback
		try {
			$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
			if ($Global:IsElevatedProcess) {
				Write-Host "🔧 Test-WindowsCompatibility: CIM query completed" -ForegroundColor Green
			}
		} catch {
			if ($Global:IsElevatedProcess) {
				Write-Host "⚠️ Test-WindowsCompatibility: CIM failed, trying WMI..." -ForegroundColor Yellow
			}
		}
		
		if (-not $os) {
			try {
				$os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
				if ($Global:IsElevatedProcess) {
					Write-Host "🔧 Test-WindowsCompatibility: WMI query completed" -ForegroundColor Green
				}
			} catch {
				if ($Global:IsElevatedProcess) {
					Write-Host "❌ Test-WindowsCompatibility: Both CIM and WMI failed" -ForegroundColor Red
				}
			}
		}
		
		if ($os) {
			$compatibility.OSVersion = $os.Version
			$compatibility.OSBuild = $os.BuildNumber
			$compatibility.Architecture = $os.OSArchitecture
			
			# Detect Windows 10/11
			if ($os.Version -like "10.*") {
				if ([int]$os.BuildNumber -ge 22000) {
					$compatibility.IsWindows11 = $true
					$compatibility.CompatibilityLevel = "Windows 11"
				} else {
					$compatibility.IsWindows10 = $true
					$compatibility.CompatibilityLevel = "Windows 10"
				}
			}
			
			# Detect ARM64
			if ($os.OSArchitecture -like "*ARM64*") {
				$compatibility.IsARM64 = $true
			}
		}
		
		# PowerShell version
		$compatibility.PowerShellVersion = $PSVersionTable.PSVersion.ToString()
		
		# Test CIM support
		try {
			$null = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
			$compatibility.SupportsCIM = $true
		} catch {
			$compatibility.SupportsCIM = $false
		}
		
		# Test WMI support
		try {
			$null = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
			$compatibility.SupportsWMI = $true
		} catch {
			$compatibility.SupportsWMI = $false
		}
		
		# Log compatibility info only if logging is available
		try {
			Write-LogEntry "Compatibility: OS=$($compatibility.CompatibilityLevel), Build=$($compatibility.OSBuild), Arch=$($compatibility.Architecture), PS=$($compatibility.PowerShellVersion)" "INFO"
		} catch {
			# Silent fallback - don't break initialization
		}
		
	} catch {
		try {
			Write-LogEntry "Error checking Windows compatibility: $($_.Exception.Message)" "ERROR"
		} catch {
			# Silent fallback - don't break initialization
		}
	}
	
	return $compatibility
}

function Get-SystemInfoCompat {
	param($Compatibility)
	
	$systemInfo = @{
		OSName = $null
		OSArchitecture = $null
		CPUName = $null
		RAMSize = $null
		GPUName = $null
		PowerShellVersion = $null
	}
	
	try {
		# Use CIM if supported, fallback to WMI
		if ($Compatibility.SupportsCIM) {
			$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
			$cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
			$ram = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
			$gpu = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*Basic*" } | Select-Object -First 1
		} else {
			$os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
			$cpu = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue
			$ram = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
			$gpu = Get-WmiObject -Class Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*Basic*" } | Select-Object -First 1
		}
		
		if ($os) { $systemInfo.OSName = $os.Caption }
		if ($cpu) { $systemInfo.CPUName = $cpu.Name }
		if ($ram) { $systemInfo.RAMSize = [math]::Round($ram.TotalPhysicalMemory / 1GB, 2) }
		if ($gpu) { $systemInfo.GPUName = $gpu.Name }
		$systemInfo.PowerShellVersion = $PSVersionTable.PSVersion.ToString()
		$systemInfo.OSArchitecture = if ($os) { $os.OSArchitecture } else { "Unknown" }
		
	} catch {
		Write-LogEntry "Error collecting system info: $($_.Exception.Message)" "ERROR"
	}
	
	return $systemInfo
}

# ==================== ADMIN ELEVATION CHECK ====================

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-AdminElevation {
    try {
        Write-Host "🔐 Program memerlukan hak akses Administrator" -ForegroundColor Yellow
        Write-Host "📋 Fitur yang memerlukan admin: Registry repair, Winsock reset, Service management" -ForegroundColor Cyan
        Write-Host "💡 Jalankan PowerShell sebagai Administrator dan jalankan script ini lagi" -ForegroundColor Cyan
        Write-Host "🔗 Atau download manual dari: https://github.com/RumiKurumi/RMRBLXCKR" -ForegroundColor Cyan
        Write-Host "⏳ Program akan menutup dalam 2 detik..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        exit 1
    } catch {
        Write-Host ("❌ Error: {0}" -f ($_.Exception.Message)) -ForegroundColor Red
        exit 1
    }
}
                
                # Test downloaded script syntax
                Write-ColorText "🔍 Memverifikasi script yang didownload..." -Color $Colors.Info
                try {
                    $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $tempScript -Raw), [ref]$null)
                    Write-LogEntry "Script syntax validation passed" "INFO"
                } catch {
                    Write-LogEntry "Script syntax validation failed: $($_.Exception.Message)" "ERROR"
                    throw "Downloaded script has syntax errors: $($_.Exception.Message)"
                }
                
                # Start elevated process with downloaded script and elevation flag

                Write-LogEntry "Starting elevated process with script: $tempScript" "INFO"
                
                # Start elevated process without waiting (non-blocking)

                
                # Give elevated process time to start
                Start-Sleep -Seconds 2
                
                # Check if elevated process is running
                if ($process -and -not $process.HasExited) {
                    Write-ColorText "✅ Elevated process started successfully (PID: $($process.Id))" -Color $Colors.Success
                    Write-LogEntry "Elevated process started successfully with PID: $($process.Id)" "INFO"
                    
                    # Cleanup temporary script after successful elevation
                    try {
                        if (Test-Path $tempScript) {
                            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
                            Write-LogEntry "Cleaned up temporary script: $tempScript" "INFO"
                        }
                    } catch {
                        Write-LogEntry "Failed to cleanup temporary script: $($_.Exception.Message)" "WARNING"
                    }
                    
                    # Close non-elevated terminal
                    Write-ColorText "🔄 Menutup terminal non-elevated..." -Color $Colors.Info
                    Write-ColorText "📋 Elevated terminal akan terbuka dalam beberapa detik..." -Color $Colors.Success
                    Start-Sleep -Seconds 2
                    
                    # Exit non-elevated process
                    exit 0
                } else {
                    Write-LogEntry "Elevated process failed to start" "WARNING"
                    Write-ColorText "⚠️ Elevated process gagal dimulai" -Color $Colors.Warning
                    
                    # Analyze failure
                    Write-ColorText "🔍 Analisis: Kemungkinan PowerShell version requirement atau permission issue" -Color $Colors.Warning
                    Write-ColorText "💡 Solusi: Jalankan PowerShell sebagai Administrator atau update PowerShell" -Color $Colors.Info
                    
                    # Don't exit immediately, let user see the error
                    Write-ColorText "⏳ Program akan melanjutkan dengan fitur terbatas..." -Color $Colors.Info
                    Start-Sleep -Seconds 3


}

# ==================== REMOTE EXECUTION HANDLER ====================

function Invoke-RemoteExecution {
    try {
        # Check if running from irm | iex (no local file)
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath) { $scriptPath = $PSCommandPath }
        
        if (-not $scriptPath) {
            # Running from irm | iex - download and run
            $tempScript = "$env:TEMP\RobloxChecker_Remote.ps1"
            $scriptUrl = "https://raw.githubusercontent.com/RumiKurumi/RMRBLXCKR/refs/heads/main/refs/heads/rumiscript/run/RobloxCheckerv2.ps1"
            
            Write-Host "📥 Downloading Roblox Checker Script..." -ForegroundColor Cyan
            $downloadSuccess = Show-DownloadProgress -Url $scriptUrl -OutFile $tempScript -Description "Downloading Roblox Checker Script"
            
            if (-not $downloadSuccess) {
                throw "Download failed"
            }
            
            # Verify download completion
            Write-Host "🔍 Memverifikasi download..." -ForegroundColor Cyan
            Start-Sleep -Seconds 1
            
            if (-not (Test-Path $tempScript)) {
                throw "Downloaded script not found after verification"
            }
            
            $finalSize = (Get-Item $tempScript).Length
            if ($finalSize -lt 1000) {
                throw "Downloaded script too small ($finalSize bytes), may be corrupted"
            }
            
            Write-Host ("✅ Download verification berhasil ({0} KB)" -f ([math]::Round($finalSize / 1KB, 1))) -ForegroundColor Green
            
            # Verify script content
            Write-Host "🔍 Memverifikasi script yang didownload..." -ForegroundColor Cyan
            try {
                $scriptContent = Get-Content $tempScript -Raw -ErrorAction Stop
                if (-not $scriptContent -or $scriptContent.Length -lt 1000) {
                    throw "Downloaded script content is empty or too small"
                }
                
                # Basic syntax check
                $null = [System.Management.Automation.PSParser]::Tokenize($scriptContent, [ref]$null)
                Write-Host "✅ Script syntax verification berhasil" -ForegroundColor Green
            } catch {
                Write-Host ("❌ Script syntax validation failed: {0}" -f ($_.Exception.Message)) -ForegroundColor Red
                throw "Downloaded script has syntax errors: $($_.Exception.Message)"
            }
            
            # Register cleanup for temp file
            $Global:TempScriptToCleanup = $tempScript
            
            # Execute downloaded script
            Write-Host "🚀 Menjalankan script yang didownload..." -ForegroundColor Cyan
            & $tempScript
            
            # Cleanup temp file after execution
            try {
                if (Test-Path $tempScript) {
                    Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
                }
            } catch {}
            
            exit 0
        }
    } catch {
        Write-Host ("❌ Error dalam remote execution: {0}" -f ($_.Exception.Message)) -ForegroundColor Red
        
        # Cleanup on error
        try {
            if ($Global:TempScriptToCleanup -and (Test-Path $Global:TempScriptToCleanup)) {
                Remove-Item $Global:TempScriptToCleanup -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        
        exit 1
    }
}

# ==================== UTILITY FUNCTIONS ====================

function Write-ColorText {
    param(
        [string]$Text,
        [string]$Color = 'White',
        [switch]$NoNewLine
    )
    
    if ($NoNewLine) {
        Write-Host $Text -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Write-LogEntry {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Robust logging - handle cases where LogFile is not yet initialized
    if ($Global:LogFile -and $Global:LogFile -ne "" -and (Test-Path (Split-Path $Global:LogFile -Parent))) {
        try {
            Add-Content -Path $Global:LogFile -Value $logEntry -Encoding UTF8
        } catch {
            # Ignore log write errors to prevent infinite loops
            # Write to console as fallback for critical errors
            if ($Level -eq 'ERROR') {
                Write-Host "LOG ERROR: $Message" -ForegroundColor Red
            }
        }
    } else {
        # Fallback logging to console for early initialization errors
        if ($Level -eq 'ERROR') {
            Write-Host "INIT ERROR: $Message" -ForegroundColor Red
        }
    }
    
    if ($Debug -and $Level -eq 'DEBUG') {
        Write-ColorText "DEBUG: $Message" -Color $Colors.Debug
    }
}

function Show-LoadingSpinner {
    param(
        [string]$Text = "Memproses",
        [int]$Duration = 3
    )
    
    $spinners = @('|', '/', '-', '\')
    $counter = 0
    $endTime = (Get-Date).AddSeconds($Duration)
    
    Write-Host ""
    while ((Get-Date) -lt $endTime) {
        $spinner = $spinners[$counter % 4]
        Write-ColorText "`r$spinner $Text..." -Color $Colors.Accent -NoNewLine
        Start-Sleep -Milliseconds 200
        $counter++
    }
    Write-Host ""
}

# Banner khusus untuk instalasi WARP (simplified dan clean)
function Show-WarpInstallBanner {
	param(
		[string]$Subtitle = "Silent Warping, harap tunggu gess.."
	)

	# Simplified banner yang lebih clean dan tidak ada artifact
	$banner = @"
╔══════════════════════════════════════════════════════════════╗
║                    🌐 CLOUDFLARE WARP 🌐                    ║
║                                                              ║
║                ██████████████████████████                   ║
║                ██░░░░░░░░░░░░░░░░░░░░░░██                   ║
║                ██░░░░░░░░░░░░░░░░░░░░░░██                   ║
║                ██░░░░░░░░░░░░░░░░░░░░░░██                   ║
║                ██░░░░░░░░░░░░░░░░░░░░░░██                   ║
║                ██████████████████████████                   ║
║                                                              ║
║              🚀 SILENT INSTALLATION MODE                    ║
╚══════════════════════════════════════════════════════════════╝
"@

	# Clean terminal redraw tanpa artifact
	try { 
		Clear-Host 
		Start-Sleep -Milliseconds 100  # Small delay untuk stabilitas
	} catch {}
	
	Write-ColorText $banner -Color $Colors.Accent
	Write-Host ""
	Write-ColorText ("🎯 " + $Subtitle) -Color $Colors.Accent
	Write-Host ""
}

# Fungsi untuk menjalankan dan memverifikasi WARP VPN (simplified dan clean)
function Start-CloudflareWARP {
	param([switch]$WhatIf)
	
	Write-LogEntry "Starting Cloudflare WARP VPN" "INFO"
	
	# Clean header untuk auto-connect section
	Write-Host ""
	Write-ColorText "🌐 AUTO-CONNECT WARP VPN" -Color $Colors.Header
	Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
	Write-Host ""
	
	# Cek apakah WARP sudah terinstall
	$warpInstalled = Test-CloudflareWARPInstalled
	if (-not $warpInstalled.Installed) {
		Write-ColorText "❌ Cloudflare WARP belum terinstall" -Color $Colors.Error
		return @{ Connected = $false; Method = 'NotInstalled'; PID = $null; Service = $null }
	}
	
	$warpCliPath = $null
	$possiblePaths = @(
		(Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\warp-cli.exe'),
		(Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\warp.exe'),
		(Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\Cloudflare WARP.exe')
	)
	
	foreach ($path in $possiblePaths) {
		if (Test-Path $path) {
			$warpCliPath = $path
			break
		}
	}
	
	if (-not $warpCliPath) {
		Write-ColorText "❌ WARP CLI tidak ditemukan" -Color $Colors.Error
		return @{ Connected = $false; Method = 'CLINotFound'; PID = $null; Service = $null }
	}
	
	Write-ColorText "🔧 Mempersiapkan WARP VPN..." -Color $Colors.Info
	
	try {
		# Check if WARP needs initial setup
		Write-ColorText "🔍 Memeriksa status WARP..." -Color $Colors.Info
		$null = Start-Process $warpCliPath -ArgumentList "status" -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\warp_initial_status.txt" -ErrorAction SilentlyContinue
		
		$initialStatus = ""
		if (Test-Path "$env:TEMP\warp_initial_status.txt") {
			$initialStatus = Get-Content "$env:TEMP\warp_initial_status.txt" -Raw
			Remove-Item "$env:TEMP\warp_initial_status.txt" -Force -ErrorAction SilentlyContinue
		}
		
		# Check if WARP needs registration
		if ($initialStatus -like "*Registration Missing*" -or $initialStatus -like "*Manual deletion*" -or $initialStatus -like "*Unable*") {
			Write-ColorText "⚠️ Auto-connect WARP gagal - Setup manual diperlukan" -Color $Colors.Warning
			Write-Host ""
			Write-ColorText "📋 Setup WARP secara manual:" -Color $Colors.Info
			Write-ColorText "   1. WARP sudah running di system tray (kanan bawah)" -Color $Colors.Info
			Write-ColorText "   2. Klik kanan icon WARP → 'Sign In' atau 'Enable WARP'" -Color $Colors.Info
			Write-ColorText "   3. Ikuti wizard setup dan accept agreement" -Color $Colors.Info
			Write-ColorText "   4. Setelah setup selesai, WARP akan otomatis connect" -Color $Colors.Info
			Write-Host ""
			Write-ColorText "💡 WARP sudah running, setup dari system tray saja" -Color $Colors.Info
			Write-ColorText "✅ Setelah setup manual selesai, WARP akan running otomatis" -Color $Colors.Success
			Write-Host ""
			return @{ Connected = $false; Method = 'NeedsManualSetup'; PID = $null; Service = $null; Status = $initialStatus }
		}
		
		# Register WARP service untuk startup
		Write-ColorText "⚙️ Mengatur startup service..." -Color $Colors.Info
		$proc = Start-Process $warpCliPath -ArgumentList "register" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
		if ($proc.ExitCode -eq 0) {
			Write-ColorText "✅ Startup service berhasil diatur" -Color $Colors.Success
		}
		
		# Connect ke WARP VPN
		Write-ColorText "🔗 Menyambungkan ke WARP VPN..." -Color $Colors.Info
		$proc = Start-Process $warpCliPath -ArgumentList "connect" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
		
		Start-Sleep -Seconds 3  # Reduced delay untuk stabilitas
		
		# Verifikasi koneksi
		Write-ColorText "🔍 Memverifikasi koneksi WARP..." -Color $Colors.Info
		$null = Start-Process $warpCliPath -ArgumentList "status" -PassThru -Wait -WindowStyle Hidden -RedirectStandardOutput "$env:TEMP\warp_status.txt" -ErrorAction SilentlyContinue
		
		$status = ""
		if (Test-Path "$env:TEMP\warp_status.txt") {
			$status = Get-Content "$env:TEMP\warp_status.txt" -Raw
			Remove-Item "$env:TEMP\warp_status.txt" -Force -ErrorAction SilentlyContinue
		}
		
		# Cek process WARP yang berjalan
		$warpProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object { 
			$_.ProcessName -like '*warp*' -or $_.ProcessName -like '*cloudflare*' 
		}
		
		# Cek service WARP
		$warpServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
			$_.Name -like '*WARP*' -or $_.DisplayName -like '*Cloudflare*WARP*' 
		}
		
		$isConnected = $status -like "*Connected*" -or $status -like "*connected*"
		
		if ($isConnected) {
			Write-ColorText "✅ WARP VPN berhasil tersambung!" -Color $Colors.Success
			Write-ColorText "🌍 Status: $status" -Color $Colors.Info
			
			if ($warpProcesses) {
				foreach ($proc in $warpProcesses) {
					Write-ColorText "🔄 Process: $($proc.ProcessName) (PID: $($proc.Id))" -Color $Colors.Success
				}
			}
			
			if ($warpServices) {
				foreach ($svc in $warpServices) {
					Write-ColorText "⚙️ Service: $($svc.Name) ($($svc.Status))" -Color $Colors.Success
				}
			}
			
			Write-LogEntry "WARP VPN connected successfully. Status: $status" "SUCCESS"
			return @{ 
				Connected = $true; 
				Method = 'VPN'; 
				PID = ($warpProcesses | Select-Object -First 1).Id; 
				Service = ($warpServices | Select-Object -First 1).Name;
				Status = $status
			}
		} else {
			Write-ColorText "⚠️ WARP VPN gagal tersambung" -Color $Colors.Warning
			Write-ColorText "📋 Status: $status" -Color $Colors.Info
			Write-LogEntry "WARP VPN connection failed. Status: $status" "WARNING"
			
			# Clean footer untuk failed connection
			Write-Host ""
			Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
			Write-ColorText "❌ AUTO-CONNECT WARP GAGAL" -Color $Colors.Error
			Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
			Write-Host ""
			
			return @{ Connected = $false; Method = 'ConnectionFailed'; PID = $null; Service = $null; Status = $status }
		}
		
		# Clean footer untuk successful connection
		Write-Host ""
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		Write-ColorText "✅ AUTO-CONNECT WARP BERHASIL" -Color $Colors.Success
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		Write-Host ""
		
	} catch {
		Write-ColorText "❌ Error menjalankan WARP VPN: $($_.Exception.Message)" -Color $Colors.Error
		Write-LogEntry "Error starting WARP VPN: $($_.Exception.Message)" "ERROR"
		
		# Clean footer untuk error
		Write-Host ""
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		Write-ColorText "❌ AUTO-CONNECT WARP ERROR" -Color $Colors.Error
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		Write-Host ""
		
		return @{ Connected = $false; Method = 'Error'; PID = $null; Service = $null }
	}
}

function Show-ProgressBar {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

function Get-TimeBasedGreeting {
    $hour = (Get-Date).Hour
    $computerName = $env:COMPUTERNAME
    
    if ($hour -lt 12) {
        return "Selamat pagi, $computerName! 🌅"
    } elseif ($hour -lt 17) {
        return "Selamat siang, $computerName! ☀️"
    } elseif ($hour -lt 19) {
        return "Selamat sore, $computerName! 🌇"
    } else {
        return "Selamat malam, $computerName! 🌙"
    }
}

function Initialize-Environment {
	# Debug: Show we're in Initialize-Environment
	if ($Global:IsElevatedProcess) {
		Write-Host "🔧 Initialize-Environment: Starting..." -ForegroundColor Yellow
	}
	
	# Initialize logging first before any other operations
	try {
		Write-LogEntry "Initializing Roblox Checker environment" "INFO"
		if ($Global:IsElevatedProcess) {
			Write-Host "🔧 Initialize-Environment: Logging initialized" -ForegroundColor Green
		}
	} catch {
		Write-Host "⚠️ Initialize-Environment: Logging error - $($_.Exception.Message)" -ForegroundColor Red
		Start-Sleep -Seconds 1
	}
	
	# Check Windows compatibility first
	if ($Global:IsElevatedProcess) {
		Write-Host "🔧 Initialize-Environment: Testing Windows compatibility..." -ForegroundColor Yellow
	}
	
	try {
		$Global:WindowsCompatibility = Test-WindowsCompatibility
		if ($Global:IsElevatedProcess) {
			Write-Host "🔧 Initialize-Environment: Windows compatibility test completed" -ForegroundColor Green
		}
	} catch {
		Write-Host "❌ Initialize-Environment: Windows compatibility test failed - $($_.Exception.Message)" -ForegroundColor Red
		Start-Sleep -Seconds 2
		throw
	}
	
	# Display compatibility info
	Write-ColorText "🔍 Deteksi Kompatibilitas Windows..." -Color $Colors.Info
	Write-ColorText "📋 OS: $($Global:WindowsCompatibility.CompatibilityLevel)" -Color $Colors.Info
	Write-ColorText "🏗️ Arsitektur: $($Global:WindowsCompatibility.Architecture)" -Color $Colors.Info
	Write-ColorText "⚡ PowerShell: $($Global:WindowsCompatibility.PowerShellVersion)" -Color $Colors.Info
	
	if ($Global:WindowsCompatibility.IsARM64) {
		Write-ColorText "🆕 ARM64 Architecture Detected" -Color $Colors.Warning
	}
	
	# Tentukan folder log di Desktop (logschecker) jika tidak ditentukan
	try {
		$desktopPath = [Environment]::GetFolderPath('Desktop')
		$preferredLogPath = Join-Path $desktopPath 'logschecker'
		# Jika user tidak mengatur LogPath atau masih default lama (TEMP), pakai Desktop\logschecker
		if (-not $LogPath -or $LogPath -eq "$env:TEMP\RobloxChecker") {
			$script:LogPath = $preferredLogPath
		} else {
			$script:LogPath = $LogPath
		}
	} catch {
		# Fallback ke TEMP jika terjadi error
		$script:LogPath = "$env:TEMP\RobloxChecker"
	}
	
	# Create log directory
	if (-not (Test-Path $script:LogPath)) {
		try {
			New-Item -Path $script:LogPath -ItemType Directory -Force | Out-Null
			Write-LogEntry "Created log directory: $script:LogPath" "INFO"
		} catch {
			Write-ColorText "⚠️ Tidak dapat membuat folder log: $($_.Exception.Message)" -Color $Colors.Warning
		}
	}
	
	# Set log file path
	$Global:LogFile = Join-Path $script:LogPath "RobloxChecker_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
	
	# Log system info - only after LogFile is properly initialized
	try {
		Write-LogEntry "=== ROBLOX CHECKER SESSION STARTED ===" "INFO"
		Write-LogEntry "Script Version: $Global:ScriptVersion" "INFO"
		Write-LogEntry "Computer: $env:COMPUTERNAME" "INFO"
		Write-LogEntry "User: $env:USERNAME" "INFO"
		Write-LogEntry "Compatibility: $($Global:WindowsCompatibility.CompatibilityLevel) Build $($Global:WindowsCompatibility.OSBuild) $($Global:WindowsCompatibility.Architecture)" "INFO"
	} catch {
		# Silent fallback - logging not ready yet
	}
}

function Write-TypewriterText {
    param(
        [string]$Text,
        [string]$Color = 'White',
        [int]$Delay = 15
    )
    foreach ($char in $Text.ToCharArray()) {
        Write-Host -NoNewline $char -ForegroundColor $Color
        Start-Sleep -Milliseconds $Delay
    }
    Write-Host
}

function Show-LoadingBar {
    param(
        [string]$Text = "Memproses",
        [int]$Duration = 2
    )
    $barLength = 30
    $step = $Duration * 10
    for ($i = 1; $i -le $step; $i++) {
        $progress = [math]::Round(($i / $step) * $barLength)
        $bar = ('#' * $progress).PadRight($barLength, '-')
        Write-Host ("`r[$bar] $Text...") -NoNewline -ForegroundColor $Colors.Accent
        Start-Sleep -Milliseconds 100
    }
    Write-Host
}

# Contoh penggunaan efek ketik dan loading bar di header/menu/proses utama
function Show-Header {
	Clear-Host
	$greeting = Get-TimeBasedGreeting
	Write-TypewriterText "╔══════════════════════════════════════════════════════════════╗" $Colors.Header 2
	Write-TypewriterText "║                                                              ║" $Colors.Header 2
	Write-TypewriterText "║               🎮 ROBLOX CHECKER BY RUMI 🎮                   ║" $Colors.Header 2
	Write-TypewriterText "║                    Version $Global:ScriptVersion                             ║" $Colors.Header 2
	Write-TypewriterText "║                                                              ║" $Colors.Header 2
	Write-TypewriterText "╚══════════════════════════════════════════════════════════════╝" $Colors.Header 2
	Write-Host ""
	Write-TypewriterText $greeting $Colors.Info 5
	Write-ColorText "Waktu: $(Get-Date -Format 'dddd, dd MMMM yyyy HH:mm:ss')" -Color $Colors.Info
	Write-Host ""
	# Tandai posisi awal area konten di bawah header
	try { $Global:ContentStartY = [Console]::CursorTop } catch { $Global:ContentStartY = 15 }
}

function Show-Menu {
    Write-Host ""
    Write-TypewriterText "🎯 PILIHAN TINDAKAN" $Colors.Header 4
    Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
    Write-TypewriterText "1. 🔍 Diagnosis Lengkap (Recommended)" $Colors.Accent 2
    Write-TypewriterText "2. 🔧 Perbaikan Otomatis" $Colors.Accent 2
    Write-TypewriterText "3. 📊 Lihat Laporan Sistem" $Colors.Accent 2
    Write-TypewriterText "4. 🧹 Bersihkan Cache Saja" $Colors.Accent 2
    Write-TypewriterText "5. ❌ Keluar" $Colors.Accent 2
    Write-Host ""
    Write-ColorText "Pilihan Anda (1-5): " -Color $Colors.Info -NoNewLine
}

function Get-UserChoice {
    do {
        $choice = Read-Host
        if ($choice -match '^[1-5]$') {
            return [int]$choice
        } else {
            Write-ColorText "❌ Pilihan tidak valid. Masukkan angka 1-5: " -Color $Colors.Error -NoNewLine
        }
    } while ($true)
}

# Konfirmasi tiga opsi: Y / N / S (Skip)
function Confirm-ActionEx {
    param([string]$Message)
    Write-ColorText ("$Message (Y=Ya / N=Tidak / S=Skip): ") -Color $Colors.Warning -NoNewLine
    do {
        $response = Read-Host
        if ($response -match '^[YyNnSs]$') {
            $ret = 'Skip'
            if ($response -match '^[Yy]$') { $ret = 'Yes' }
            elseif ($response -match '^[Nn]$') { $ret = 'No' }
            Write-LogEntry ("UserPrompt: '" + $Message + "' -> " + $ret) "INFO"
            return $ret
        } else {
            Write-ColorText "❌ Jawab dengan Y, N, atau S: " -Color $Colors.Error -NoNewLine
        }
    } while ($true)
}

# Cek kesehatan executable Roblox
function Get-ExecutableHealth {
    param([string]$ExecutablePath)
    $result = @{ Exists = $false; SizeBytes = 0; IsSigned = $false; SignatureStatus = 'Unknown'; Health = 'Tidak ditemukan' }
    try {
        if ($ExecutablePath -and (Test-Path $ExecutablePath)) {
            $result.Exists = $true
            $fi = Get-Item $ExecutablePath -ErrorAction SilentlyContinue
            if ($fi) { $result.SizeBytes = $fi.Length }
            $sig = Get-AuthenticodeSignature -FilePath $ExecutablePath -ErrorAction SilentlyContinue
            if ($sig) {
                $result.IsSigned = ($null -ne $sig.SignerCertificate)
                $result.SignatureStatus = [string]$sig.Status
            }
            if ($result.SizeBytes -gt 0 -and ($result.SignatureStatus -eq 'Valid' -or -not $result.IsSigned)) {
                $result.Health = 'Aman'
            } elseif ($result.SizeBytes -eq 0) {
                $result.Health = 'Rusak (0 byte)'
            } else {
                $result.Health = 'Perlu dicek (tanda tangan tidak valid)'
            }
        }
    } catch {}
    return $result
}

# Uji konektivitas Roblox (Ping + HTTP)
function Test-RobloxConnectivity {
    $conn = @{ PingOk = $false; HttpOkMain = $false; HttpOkApi = $false; Detail = @() }
    try {
        $ping = Test-Connection "roblox.com" -Count 1 -Quiet -ErrorAction SilentlyContinue -TimeoutSeconds 2
        $conn.PingOk = [bool]$ping
        if (-not $conn.PingOk) { $conn.Detail += 'Ping roblox.com gagal' }
    } catch { $conn.Detail += 'Ping error' }
    try {
        $r1 = Invoke-WebRequest -Method Head -Uri 'https://www.roblox.com' -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
        $conn.HttpOkMain = [bool]($r1 -and $r1.StatusCode -ge 200 -and $r1.StatusCode -lt 400)
        if (-not $conn.HttpOkMain) { $conn.Detail += 'HTTP https://www.roblox.com gagal' }
    } catch { $conn.Detail += 'HTTP main error' }
    try {
        $r2 = Invoke-WebRequest -Method Head -Uri 'https://apis.roblox.com' -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
        $conn.HttpOkApi = [bool]($r2 -and $r2.StatusCode -ge 200 -and $r2.StatusCode -lt 400)
        if (-not $conn.HttpOkApi) { $conn.Detail += 'HTTP https://apis.roblox.com gagal' }
    } catch { $conn.Detail += 'HTTP api error' }
    return $conn
}

# ==================== SYSTEM DETECTION FUNCTIONS ====================

function Get-SystemInfo {
    Write-LogEntry "Collecting system information" "INFO"
    Show-ProgressBar -Activity "Mengumpulkan Informasi Sistem" -Status "Mendapatkan detail sistem..." -PercentComplete 10
    
    try {
        # Use compatibility-aware system info collection
        $systemInfo = Get-SystemInfoCompat -Compatibility $Global:WindowsCompatibility
        
        # Add additional info
        $systemInfo.Username = $env:USERNAME
        $systemInfo.ComputerName = $env:COMPUTERNAME
        
        # Get CPU cores if available
        if ($Global:WindowsCompatibility.SupportsCIM) {
            $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue
        } else {
            $cpu = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue
        }
        if ($cpu) {
            $systemInfo.CPUCores = $cpu.NumberOfCores
        }
        
        Write-LogEntry "System info collected successfully" "SUCCESS"
        return $systemInfo
    } catch {
        Write-LogEntry "Error collecting system info: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-ARM64Compatibility {
	param($Compatibility)
	
	$arm64Info = @{
		IsARM64 = $false
		EmulationMode = $false
		CompatibilityIssues = @()
		Recommendations = @()
	}
	
	if ($Compatibility.IsARM64) {
		$arm64Info.IsARM64 = $true
		
		# Check for x64 emulation
		try {
			$envVars = @("PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432")
			foreach ($var in $envVars) {
				$envValue = (Get-Item "env:$var" -ErrorAction SilentlyContinue).Value
				if ($envValue -like "*AMD64*") {
					$arm64Info.EmulationMode = $true
					break
				}
			}
		} catch {}
		
		# ARM64 specific recommendations
		$arm64Info.Recommendations += "ARM64 Architecture Detected"
		$arm64Info.Recommendations += "Some features may run under x64 emulation"
		$arm64Info.Recommendations += "Performance may vary compared to native x64"
		
		Write-LogEntry "ARM64 compatibility check completed" "INFO"
	}
	
	return $arm64Info
}

function Get-RobloxInfo {
	Write-LogEntry "Detecting Roblox installation" "INFO"
	Show-ProgressBar -Activity "Mendeteksi Roblox" -Status "Mencari instalasi Roblox..." -PercentComplete 30
	
	$robloxInfo = @{
		IsInstalled = $false
		InstallPath = ""
		ExecutablePath = ""
		Version = ""
		IsRunning = $false
		ProcessCount = 0
		InstallDate = ""
		Size = 0
		ExecHealth = $null
	}
	
	$possiblePaths = @(
		"$env:LOCALAPPDATA\Roblox",
		"$env:PROGRAMFILES\Roblox",
		"$env:PROGRAMFILES(X86)\Roblox",
		"$env:APPDATA\Roblox"
	)
	foreach ($path in $possiblePaths) {
		if (Test-Path $path) {
			$robloxInfo.InstallPath = $path
			$robloxInfo.IsInstalled = $true
			Write-LogEntry "Found Roblox installation at: $path" "INFO"
			break
		}
	}
	
	# Cari executable jika folder instalasi diketahui
	if ($robloxInfo.InstallPath) {
		$exePaths = @(
			"$($robloxInfo.InstallPath)\RobloxPlayerLauncher.exe",
			"$($robloxInfo.InstallPath)\Versions\*\RobloxPlayerBeta.exe"
		)
		foreach ($exePath in $exePaths) {
			$foundExe = Get-ChildItem $exePath -ErrorAction SilentlyContinue | Select-Object -First 1
			if ($foundExe) {
				$robloxInfo.ExecutablePath = $foundExe.FullName
				try {
					$versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($foundExe.FullName)
					$robloxInfo.Version = $versionInfo.ProductVersion
				} catch { $robloxInfo.Version = "Unknown" }
				$robloxInfo.InstallDate = $foundExe.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
				break
			}
		}
		# Evaluasi kesehatan executable
		if ($robloxInfo.ExecutablePath) { $robloxInfo.ExecHealth = Get-ExecutableHealth -ExecutablePath $robloxInfo.ExecutablePath }
	}
	
	# Check running processes
	$robloxProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*Roblox*" }
	$robloxInfo.ProcessCount = $robloxProcesses.Count
	$robloxInfo.IsRunning = ($robloxInfo.IsRunning -or ($robloxProcesses.Count -gt 0))
	
	# Hitung ukuran instalasi (aman)
	if ($robloxInfo.InstallPath -and (Test-Path $robloxInfo.InstallPath)) {
		try {
			$items = Get-ChildItem -Path $robloxInfo.InstallPath -Recurse -File -ErrorAction SilentlyContinue -Force | Select-Object -First 50000
			$totalSize = ($items | Measure-Object -Property Length -Sum).Sum
			$robloxInfo.Size = [math]::Round(($totalSize) / 1MB, 2)
		} catch { $robloxInfo.Size = 0 }
	}
	
	Write-LogEntry "Roblox detection completed" "INFO"
	return $robloxInfo
}

# Helper: Deteksi MSVC Redistributable via Registry (lebih cepat, tidak memicu MSI reconfiguration)
function Get-MsvcRedistInfo {
	$uninstallPaths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
	)
	$msvcEntries = @()
	foreach ($path in $uninstallPaths) {
		try {
			$items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object {
				$_.DisplayName -like "*Visual C++*Redistributable*"
			}
			if ($items) { $msvcEntries += $items }
		} catch {}
	}
	if ($msvcEntries.Count -gt 0) {
		return $msvcEntries | Select-Object -Property DisplayName, DisplayVersion | Sort-Object DisplayName -Unique
	}
	return $null
}

function Test-SystemRequirements {
    Write-LogEntry "Checking system requirements" "INFO"
    Show-ProgressBar -Activity "Memeriksa Persyaratan Sistem" -Status "Validasi kompabilitas..." -PercentComplete 50
    
    $requirements = @{
        OS = @{ Met = $false; Required = "Windows 7/8/8.1/10/11"; Current = "" }
        RAM = @{ Met = $false; Required = "1 GB"; Current = "" }
        DirectX = @{ Met = $false; Required = "DirectX 9"; Current = "" }
        DotNet = @{ Met = $false; Required = ".NET Framework 4.0+"; Current = "" }
        MSVC = @{ Met = $false; Required = "Visual C++ Redistributable"; Current = "" }
    }
    
    try {
        # Check OS - use compatibility-aware approach
        $requirements.OS.Current = $Global:WindowsCompatibility.CompatibilityLevel
        $supportedOS = @("Windows 7", "Windows 8", "Windows 10", "Windows 11", "Windows Server")
        $requirements.OS.Met = $supportedOS | Where-Object { $requirements.OS.Current -like "*$_*" }
        
        # Check RAM - use compatibility-aware approach
        if ($Global:WindowsCompatibility.SupportsCIM) {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        } else {
            $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        }
        $ramTotal = if ($cs) { $cs.TotalPhysicalMemory } else { 0 }
        $ramGB = [math]::Round($ramTotal / 1GB, 2)
        $requirements.RAM.Current = "$ramGB GB"
        $requirements.RAM.Met = $ramGB -ge 1
        
        # Check DirectX via dxdiag (multi-locale)
		try {
			$dxDiagTxt = Join-Path $env:TEMP ("dxdiag_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".txt")
			$proc = Start-Process -FilePath "dxdiag.exe" -ArgumentList "/whql:off", "/t", $dxDiagTxt -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
			if ($proc) { Wait-Process -Id $proc.Id -Timeout 15 -ErrorAction SilentlyContinue }
			if (Test-Path $dxDiagTxt) {
				$line = $null
				$patterns = @('DirectX Version','Versi DirectX')
				foreach ($p in $patterns) {
					$hit = Select-String -Path $dxDiagTxt -Pattern $p -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
					if ($hit) { $line = $hit.Line; break }
				}
				if ($line) {
					$ver = ($line -split ':',2)[1].Trim()
					$requirements.DirectX.Current = $ver
					$numMatch = [regex]::Match($ver, '(\d+)')
					if ($numMatch.Success -and [int]$numMatch.Groups[1].Value -ge 9) { $requirements.DirectX.Met = $true } else { $requirements.DirectX.Met = $true }
				} else {
					$requirements.DirectX.Current = "Tidak terdeteksi"
				}
				try { Remove-Item $dxDiagTxt -Force -ErrorAction SilentlyContinue } catch {}
			} else { $requirements.DirectX.Current = "Tidak terdeteksi" }
		} catch {
			try { $dx = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\DirectX" -Name Version -ErrorAction SilentlyContinue; if ($dx) { $requirements.DirectX.Current = $dx.Version; $requirements.DirectX.Met = $true } } catch { $requirements.DirectX.Current = "Tidak terdeteksi" }
		}
        
        # Check .NET Framework - Windows 11 compatible registry paths
        $dotNetVersions = @()
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\NET Framework Setup\NDP"
        )
        
        foreach ($regPath in $registryPaths) {
            try {
                $versions = Get-ChildItem $regPath -Recurse -ErrorAction SilentlyContinue |
                           Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
                           Where-Object { $_.PSChildName -match "^v" }
                $dotNetVersions += $versions
            } catch {
                # Continue if registry path not accessible
            }
        }
        
        if ($dotNetVersions) {
            $latestVersion = ($dotNetVersions | Sort-Object Version | Select-Object -Last 1).Version
            $requirements.DotNet.Current = $latestVersion
            $requirements.DotNet.Met = $latestVersion -ge "4.0"
        }
        
        # Check Visual C++ Redistributable via registry (bukan Win32_Product)
        $msvc = Get-MsvcRedistInfo
        if ($msvc) {
            $requirements.MSVC.Current = ($msvc | Select-Object -First 1).DisplayName
            $requirements.MSVC.Met = $true
        } else {
            $requirements.MSVC.Current = "Tidak terinstal"
        }
        
    } catch {
        Write-LogEntry "Error checking system requirements: $($_.Exception.Message)" "ERROR"
    }
    
    Write-LogEntry "System requirements check completed" "INFO"
    return $requirements
}

function Get-RobloxLogs {
	Write-LogEntry "Collecting Roblox logs" "INFO"
	Show-ProgressBar -Activity "Mengumpulkan Log" -Status "Mencari file log Roblox..." -PercentComplete 70
	
	$logInfo = @{
		Found = $false
		LogPaths = @()
		ErrorCount = 0
		CrashCount = 0
		LastCrash = ""
		ErrorSummary = @()
	}
	
	# Target copy folder: Desktop\logschecker
	try {
		$desktopPath = [Environment]::GetFolderPath('Desktop')
		$desktopLogs = Join-Path $desktopPath 'logschecker'
		if (-not (Test-Path $desktopLogs)) { New-Item -Path $desktopLogs -ItemType Directory -Force | Out-Null }
	} catch { $desktopLogs = $script:LogPath }
	
	# Common log locations
	$logPaths = @(
		"$env:LOCALAPPDATA\Roblox\logs",
		"$env:TEMP\Roblox",
		"$env:APPDATA\Roblox\logs"
	)
	
	foreach ($logPath in $logPaths) {
		if (Test-Path $logPath) {
			$logFiles = Get-ChildItem $logPath -Filter "*.log" -ErrorAction SilentlyContinue
			foreach ($logFile in $logFiles) {
				$logInfo.LogPaths += $logFile.FullName
				# Copy ke LogPath dan ke Desktop\logschecker
				try {
					$dest1 = Join-Path $script:LogPath ("roblox_" + $logFile.Name)
					$dest2 = Join-Path $desktopLogs ("roblox_" + $logFile.Name)
					Copy-Item $logFile.FullName $dest1 -ErrorAction SilentlyContinue
					Copy-Item $logFile.FullName $dest2 -ErrorAction SilentlyContinue
					$Global:TempFiles += $dest1
				} catch {}
				# Parse for errors/crash
				try {
					$lines = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
					foreach ($line in $lines) {
						if ($line -match '(?i)crash|exception|error|exit code|fatal|fail') {
							$logInfo.ErrorSummary += $line
							if ($line -match '(?i)crash') { $logInfo.CrashCount++ }
							if ($line -match '(?i)error|exception|fail|fatal') { $logInfo.ErrorCount++ }
							$logInfo.LastCrash = $line
						}
					}
				} catch {}
			}
			if ($logFiles.Count -gt 0) { $logInfo.Found = $true }
		}
	}
	Write-LogEntry "Found $($logInfo.LogPaths.Count) Roblox log files" "INFO"
	return $logInfo
}

# ==================== DIAGNOSTIC FUNCTIONS ====================

function Test-RobloxIntegrity {
    Write-LogEntry "Testing Roblox integrity" "INFO"
    
    $issues = @()
    
    # Check for corrupted files
    $robloxInfo = Get-RobloxInfo
    if ($robloxInfo.IsInstalled -and $robloxInfo.ExecutablePath) {
        try {
            $fileInfo = Get-Item $robloxInfo.ExecutablePath
            if ($fileInfo.Length -eq 0) {
                $issues += "File executable Roblox rusak (0 bytes)"
            }
        } catch {
            $issues += "Tidak dapat mengakses file executable Roblox"
        }
    }
    
    # Check registry entries
    $regPaths = @(
        "HKCU:\Software\Roblox Corporation",
        "HKLM:\SOFTWARE\WOW6432Node\Roblox Corporation"
    )
    
    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            try {
                Get-ItemProperty $regPath -ErrorAction Stop | Out-Null
            } catch {
                $issues += "Registry Roblox bermasalah: $regPath"
            }
        }
    }
    
    Write-LogEntry "Integrity check completed, found $($issues.Count) issues" "INFO"
    return $issues
}

function Test-CommonIssues {
    Write-LogEntry "Checking for common Roblox issues" "INFO"
    
    $issues = @()
    
    $robloxProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*Roblox*" }
    if ($robloxProcesses.Count -gt 1) { $issues += "Beberapa proses Roblox berjalan bersamaan ($($robloxProcesses.Count) proses)" }
    
    # Antivirus info (best effort)
    $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
    if ($antivirusProducts) { $issues += "Antivirus terdeteksi - mungkin memblokir Roblox" }
    
    # Windows Defender (best effort)
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) { $issues += "Windows Defender Real-time Protection aktif" }
    } catch {}
    
    # Disk space (C: only)
    try {
        $drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if (-not $drive) { $drive = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive } }
        $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
        if ($freeSpaceGB -lt 2) { $issues += "Ruang disk hampir penuh ($freeSpaceGB GB tersisa)" }
    } catch {}
    
    # Network connectivity (timeout cepat)
    try {
        $ping = Test-Connection "roblox.com" -Count 1 -Quiet -ErrorAction SilentlyContinue -TimeoutSeconds 2
        if (-not $ping) { $issues += "Tidak dapat terhubung ke server Roblox" }
    } catch { $issues += "Masalah koneksi internet" }
    
    Write-LogEntry "Common issues check completed, found $($issues.Count) issues" "INFO"
    return $issues
}

# ==================== REPAIR FUNCTIONS ====================

function Repair-RobloxCache {
    param([switch]$WhatIf)
    
    Write-LogEntry "Starting Roblox cache repair" "INFO"
    Write-ColorText "🔧 Membersihkan cache Roblox..." -Color $Colors.Info
    
    $cachePaths = @(
        "$env:LOCALAPPDATA\Roblox\http",
        "$env:LOCALAPPDATA\Roblox\InstalledPlugins",
        "$env:TEMP\Roblox"
    )
    
    $cleaned = 0
    foreach ($cachePath in $cachePaths) {
        if (Test-Path $cachePath) {
            try {
                if (-not $WhatIf) {
                    # Create safety backup first
                    $backupPath = "$LogPath\backup_$(Split-Path $cachePath -Leaf)_$(Get-Date -Format 'HHmmss')"
                    robocopy $cachePath $backupPath /MIR /NFL /NDL /NJH /NJS | Out-Null
                    $Global:SafetyBackups += $backupPath
                    
                    # Remove cache files safely
                    Get-ChildItem $cachePath -File -Recurse -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Extension -in @('.tmp', '.cache', '.dat') } |
                        Remove-Item -Force -ErrorAction SilentlyContinue
                    $cleaned++
                }
                Write-LogEntry "Cleaned cache: $cachePath" "SUCCESS"
            } catch {
                Write-LogEntry "Error cleaning cache $cachePath`: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    Write-ColorText "✅ Cache dibersihkan: $cleaned lokasi" -Color $Colors.Success
    return $cleaned
}

function Repair-RobloxRegistry {
    param([switch]$WhatIf)
    
    Write-LogEntry "Starting Roblox registry repair" "INFO"
    Write-ColorText "🔧 Memperbaiki registry Roblox..." -Color $Colors.Info
    
    if (-not (Test-IsAdmin)) {
        Write-ColorText "⚠️ Registry repair memerlukan hak administrator" -Color $Colors.Warning
        return $false
    }
    
    try {
        if (-not $WhatIf) {
            # Export current registry as backup
            $regBackup = "$LogPath\roblox_registry_backup.reg"
            reg export "HKEY_CURRENT_USER\Software\Roblox Corporation" $regBackup /y | Out-Null
            $Global:SafetyBackups += $regBackup
            
            # Remove problematic registry entries
            $regKeys = @(
                "HKCU:\Software\Roblox Corporation\Roblox\CachedSettings",
                "HKCU:\Software\Roblox Corporation\Roblox\LocalStorage"
            )
            
            foreach ($regKey in $regKeys) {
                if (Test-Path $regKey) {
                    Remove-Item $regKey -Recurse -Force -ErrorAction SilentlyContinue
                    Write-LogEntry "Removed registry key: $regKey" "SUCCESS"
                }
            }
        }
        
        Write-ColorText "✅ Registry diperbaiki" -Color $Colors.Success
        return $true
    } catch {
        Write-LogEntry "Registry repair error: $($_.Exception.Message)" "ERROR"
        Write-ColorText "❌ Gagal memperbaiki registry: $($_.Exception.Message)" -Color $Colors.Error
        return $false
    }
}

function Repair-RobloxProcesses {
    param([switch]$WhatIf)
    
    Write-LogEntry "Starting Roblox process cleanup" "INFO"
    Write-ColorText "🔧 Menutup proses Roblox yang bermasalah..." -Color $Colors.Info
    
    $robloxProcesses = Get-Process | Where-Object { $_.ProcessName -like "*Roblox*" }
    
    if ($robloxProcesses.Count -eq 0) {
        Write-ColorText "ℹ️ Tidak ada proses Roblox yang berjalan" -Color $Colors.Info
        return 0
    }
    
    $closedCount = 0
    foreach ($process in $robloxProcesses) {
        try {
            if (-not $WhatIf) {
                Write-ColorText "🔄 Menutup: $($process.ProcessName) (PID: $($process.Id))" -Color $Colors.Info
                $process.CloseMainWindow()
                Start-Sleep -Seconds 2
                
                if (-not $process.HasExited) {
                    $process.Kill()
                    Start-Sleep -Seconds 1
                }
                $closedCount++
            }
            Write-LogEntry "Closed Roblox process: $($process.ProcessName) (PID: $($process.Id))" "SUCCESS"
        } catch {
            Write-LogEntry "Error closing process $($process.ProcessName): $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-ColorText "✅ Proses ditutup: $closedCount" -Color $Colors.Success
    return $closedCount
}

function Install-MissingDependencies {
    param([switch]$WhatIf)
    
    Write-LogEntry "Checking and installing missing dependencies" "INFO"
    Write-ColorText "🔧 Memeriksa dependensi yang hilang..." -Color $Colors.Info
    
    $installed = 0
    
    # Check Visual C++ Redistributable via registry
    $msvc = Get-MsvcRedistInfo
    if (-not $msvc) {
        Write-ColorText "⚠️ Visual C++ Redistributable tidak ditemukan" -Color $Colors.Warning
        Write-ColorText "ℹ️ Unduh dari: https://aka.ms/vs/17/release/vc_redist.x64.exe" -Color $Colors.Info
        $installed++
    }
    
    # Check .NET Framework
    $dotNet = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse |
             Get-ItemProperty -Name Version -ErrorAction SilentlyContinue |
             Where-Object { $_.Version -ge "4.0" }
    
    if (-not $dotNet) {
        Write-ColorText "⚠️ .NET Framework 4.0+ tidak ditemukan" -Color $Colors.Warning
        Write-ColorText "ℹ️ Unduh dari Microsoft .NET Framework download page" -Color $Colors.Info
        $installed++
    }
    
    if ($installed -eq 0) {
        Write-ColorText "✅ Semua dependensi sudah terinstall" -Color $Colors.Success
    }
    
    return $installed
}

# ==================== NETWORK SAFE PACKET & UTILITIES ====================

function Clear-RobloxCacheWithBackup {
	param([switch]$WhatIf)
	
	Write-LogEntry "Starting safe Roblox cache clean with backup" "INFO"
	Write-ColorText "🧹 Membersihkan cache Roblox (dengan backup) ..." -Color $Colors.Info
	
	$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
	$backupRoot = $script:LogPath
	try { if (-not (Test-Path $backupRoot)) { New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null } } catch {}
	
	$targets = @(
		"$env:LOCALAPPDATA\Roblox\http",
		"$env:LOCALAPPDATA\Roblox\Downloads",
		"$env:LOCALAPPDATA\Roblox\ebWebView",
		"$env:LOCALAPPDATA\Roblox\CookieStore",
		"$env:TEMP\Roblox"
	)
	
	$cleaned = 0
	foreach ($dir in $targets) {
		if ([string]::IsNullOrWhiteSpace($dir)) { continue }
		if (Test-Path $dir) {
			try {
				$leaf = Split-Path $dir -Leaf
				$backupPath = Join-Path $backupRoot ("backup_" + $leaf + "_" + $timestamp)
				if (-not $WhatIf) {
					# Backup menggunakan robocopy agar cepat dan tahan error
					robocopy $dir $backupPath /MIR /NFL /NDL /NJH /NJS | Out-Null
					$Global:SafetyBackups += $backupPath
					# Hapus direktori cache secara aman
					Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
					# Buat ulang folder kosong agar aman jika aplikasi mengharapkan eksistensi folder
					New-Item -Path $dir -ItemType Directory -Force | Out-Null
				}
				$cleaned++
				Write-LogEntry "Cache cleaned with backup: $dir -> $backupPath" "SUCCESS"
			} catch {
				Write-LogEntry "Error cleaning cache $dir`: $($_.Exception.Message)" "ERROR"
			}
		}
	}
	
	Write-ColorText "✅ Cache Roblox dibersihkan: $cleaned lokasi (backup di $backupRoot)" -Color $Colors.Success
	return $cleaned
}

function Get-Port5051Usage {
	Write-LogEntry "Checking port 5051 usage" "INFO"
	$results = @()
	try {
		# Gunakan netstat sesuai instruksi pengguna agar kompatibel di semua versi
		$raw = cmd /c "netstat -ano | findstr :5051" 2>$null
		if ($raw) {
			$lines = @($raw) -split "`n"
			$pids = @()
			foreach ($line in $lines) {
				$parts = ($line -replace "\s+", " ").Trim().Split(' ')
				if ($parts.Length -ge 5) {
					$procId = $parts[$parts.Length-1]
					if ($procId -match '^[0-9]+$') { $pids += [int]$procId }
				}
			}
			$pids = $pids | Sort-Object -Unique
			foreach ($procId in $pids) {
				try {
					$proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
					$results += [pscustomobject]@{ PID = $procId; ProcessName = ($proc.ProcessName) ; MainModule = (try { $proc.MainModule.FileName } catch { $null }) }
				} catch {
					$results += [pscustomobject]@{ PID = $procId; ProcessName = "Unknown"; MainModule = $null }
				}
			}
		}
	} catch {
		Write-LogEntry "Error checking port 5051: $($_.Exception.Message)" "ERROR"
	}
	return $results
}

function Find-ConflictingApps {
	Write-LogEntry "Detecting potentially conflicting apps (G HUB/RTSS/MSI Afterburner/Crucial Momentum Cache/Steering drivers)" "INFO"
	$findings = [ordered]@{}
	$findings.RunningProcesses = @()
	$findings.InstalledApps = @()
	$findings.Services = @()

	$procPatterns = @(
		'lghub', 'lghub_agent', 'logitech', 'LGHUB',
		'rtss', 'RTSS', 'RivaTuner',
		'MSIAfterburner', 'Afterburner',
		'Momentum', 'Crucial'
	)
	try {
		$procs = Get-Process -ErrorAction SilentlyContinue
		foreach ($p in $procs) {
			foreach ($pat in $procPatterns) {
				if ($p.ProcessName -like ("*" + $pat + "*")) {
					$findings.RunningProcesses += [pscustomobject]@{ Name = $p.ProcessName; Id = $p.Id }
					break
				}
			}
		}
	} catch {}

	try {
		$uninstallPaths = @(
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
		)
		$matchTerms = @('Logitech G HUB','Logitech','RivaTuner','RTSS','MSI Afterburner','Crucial Storage Executive','Momentum Cache','Steering','Wheel')
		foreach ($path in $uninstallPaths) {
			$items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $null -ne $_.DisplayName }
			foreach ($it in $items) {
				foreach ($term in $matchTerms) {
					if ($it.DisplayName -like ("*"+$term+"*")) { $findings.InstalledApps += [pscustomobject]@{ Name = $it.DisplayName; Version = $it.DisplayVersion }; break }
				}
			}
		}
	} catch {}

	try {
		$svcTerms = @('lghub','logi','rtss','afterburner','momentum','crucial')
		$svcs = Get-Service -ErrorAction SilentlyContinue
		foreach ($s in $svcs) {
			foreach ($st in $svcTerms) {
				if ($s.Name -like ("*"+$st+"*")) { $findings.Services += [pscustomobject]@{ Name = $s.Name; Status = $s.Status }; break }
			}
		}
	} catch {}

	return $findings
}

function Test-CloudflareWARPInstalled {
	Write-LogEntry "Checking if Cloudflare WARP is already installed" "INFO"
	$result = @{ Installed = $false; Version = $null; Path = $null }
	try {
		$uninstallPaths = @(
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
			"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
		)
		$entry = $null
		foreach ($path in $uninstallPaths) {
			$items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $null -ne $_.DisplayName }
			$hit = $items | Where-Object { $_.DisplayName -like '*Cloudflare WARP*' -or $_.DisplayName -like '*Cloudflare*WARP*' } | Select-Object -First 1
			if ($hit) { $entry = $hit; break }
		}
		if ($entry) { $result.Installed = $true; $result.Version = $entry.DisplayVersion }
	} catch {}
	# File existence check - hanya jika registry sudah positif
	if ($result.Installed) {
		try {
			$paths = @(
				(Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\Cloudflare WARP.exe'),
				(Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\warp-cli.exe'),
				(Join-Path $env:ProgramFiles 'Cloudflare\Cloudflare WARP\warp.exe')
			)
			foreach ($p in $paths) { 
				if (Test-Path $p) { 
					$result.Path = $p; 
					Write-LogEntry "WARP executable found at: $p" "INFO"
					break 
				} 
			}
		} catch { Write-LogEntry "Error checking WARP files: $($_.Exception.Message)" "ERROR" }
	}
	
	# Service check - hanya jika registry sudah positif
	if ($result.Installed) {
		try {
			$svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { 
				$_.Name -like '*WARP*' -or $_.DisplayName -like '*Cloudflare*WARP*' 
			} | Select-Object -First 1
			if ($svc) { 
				Write-LogEntry "WARP service found: $($svc.Name) ($($svc.DisplayName))" "INFO"
			}
		} catch { Write-LogEntry "Error checking WARP services: $($_.Exception.Message)" "ERROR" }
	}
	if ($result.Installed) { Write-LogEntry ("Cloudflare WARP detected (Version=" + ($result.Version) + ", Path=" + ($result.Path) + ")") "INFO" } else { Write-LogEntry "Cloudflare WARP not detected" "INFO" }
	return $result
}

function Install-CloudflareWARP {
	param([switch]$WhatIf)
	
	Write-LogEntry "Installing Cloudflare WARP (latest)" "INFO"
	Write-ColorText "🌐 Mengunduh & memasang Cloudflare WARP (1.1.1.1)..." -Color $Colors.Info
	
    # Idempotent: skip if already installed
    try {
        $det = Test-CloudflareWARPInstalled
        if ($det -and $det.Installed) {
            Write-ColorText "✅ Cloudflare WARP sudah terpasang. Melewati download/install." -Color $Colors.Success
            Write-LogEntry ("WARP already installed. Version=" + $det.Version + ", Path=" + $det.Path) "INFO"
            return @{ Installed = $true; Method = 'AlreadyInstalled'; File = $null; ExitCode = 0; Version = $det.Version; Path = $det.Path }
        }
    } catch {}

	if ($WhatIf) { Write-LogEntry "WhatIf: skipping download/install WARP" "INFO"; return @{ Installed = $false; Method = 'Skipped'; File = $null; ExitCode = $null } }
	
	try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
	
	$downloadUrl = 'https://1111-releases.cloudflareclient.com/win/latest'
	$tempRoot = Join-Path $env:TEMP 'RobloxChecker'
	try { if (-not (Test-Path $tempRoot)) { New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null } } catch {}
	
	Write-ColorText "📥 Mengunduh dari: $downloadUrl" -Color $Colors.Info
	Write-ColorText "📁 Folder temporary: $tempRoot" -Color $Colors.Info
	
	$resp = $null
	$targetFile = Join-Path $tempRoot ("CloudflareWARP_latest")
	try {
		Write-ColorText "🔍 Mendeteksi nama file dari server..." -Color $Colors.Info
		$resp = Invoke-WebRequest -Uri $downloadUrl -Method Get -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop
		$fname = $null
		if ($resp.Headers.'Content-Disposition') {
			$cd = $resp.Headers.'Content-Disposition'
			if ($cd -match 'filename="?([^";]+)') { $fname = $Matches[1] }
		}
		if (-not $fname) {
			try { $fname = [IO.Path]::GetFileName($resp.BaseResponse.ResponseUri.LocalPath) } catch { $fname = 'CloudflareWARP_latest.msi' }
		}
		$targetFile = Join-Path $tempRoot $fname
		
		Write-ColorText "📋 Nama file: $fname" -Color $Colors.Info
		
		# Get real file size
		$realSize = 0
		try {
			$realSize = $resp.ContentLength
			if ($realSize -gt 0) {
				$sizeMB = [math]::Round($realSize / 1MB, 2)
				Write-ColorText "💾 Ukuran: $sizeMB MB" -Color $Colors.Info
			} else {
				Write-ColorText "💾 Ukuran: Mendeteksi..." -Color $Colors.Info
			}
		} catch {
			Write-ColorText "💾 Ukuran: Mendeteksi..." -Color $Colors.Info
		}
		
		Write-ColorText "⏳ Mengunduh file..." -Color $Colors.Info
		
		# Download with visual progress
		$downloadSuccess = Show-DownloadProgress -Url $downloadUrl -OutFile $targetFile -Description "Downloading Cloudflare WARP"
		
		if (-not $downloadSuccess) {
			throw "Download failed with progress bar method"
		}
		
		# Verifikasi file berhasil didownload
		if (Test-Path $targetFile) {
			$fileSize = (Get-Item $targetFile).Length
			$fileSizeMB = [math]::Round($fileSize / 1MB, 2)
			Write-ColorText "✅ Download berhasil!" -Color $Colors.Success
			Write-ColorText "📁 Lokasi: $targetFile" -Color $Colors.Success
			Write-ColorText "📊 Ukuran file: $fileSizeMB MB" -Color $Colors.Success
			Write-LogEntry "Downloaded WARP to: $targetFile (Size: $fileSizeMB MB)" "SUCCESS"
		} else {
			throw "File tidak ditemukan setelah download"
		}
	} catch {
		Write-ColorText "❌ Gagal mengunduh WARP: $($_.Exception.Message)" -Color $Colors.Error
		Write-LogEntry "Failed to download WARP: $($_.Exception.Message)" "ERROR"
		return @{ Installed = $false; Method = 'DownloadFailed'; File = $null; ExitCode = -1 }
	}

	$ext = [IO.Path]::GetExtension($targetFile).ToLower()
	$exitCode = $null
	$method = ''
	
	# Tampilkan banner instalasi khusus WARP
	Show-WarpInstallBanner "Silent Warping, harap tunggu gess.."
	Start-Sleep -Seconds 1  # Reduced delay untuk transisi yang lebih smooth
	
	try {
		Write-ColorText "🔧 Memulai instalasi silent..." -Color $Colors.Info
		
		if ($ext -eq '.msi') {
			$method = 'MSI Silent (/qn /norestart)'
			Write-ColorText "📦 Menggunakan MSI installer dengan mode silent" -Color $Colors.Info
			$proc = Start-Process msiexec.exe -ArgumentList "/i `"$targetFile`" /qn /norestart /log `"$tempRoot\warp_install.log`"" -PassThru -Wait -WindowStyle Hidden
			$exitCode = $proc.ExitCode
		} elseif ($ext -eq '.exe') {
			$method = 'EXE Silent (/S /quiet)'
			Write-ColorText "📦 Menggunakan EXE installer dengan mode silent" -Color $Colors.Info
			
			# Coba berbagai argumen silent yang umum
			$silentArgs = @("/S", "/quiet", "/silent", "/VERYSILENT", "/sp-", "/suppressmsgboxes")
			$proc = $null
			
			foreach ($arg in $silentArgs) {
				try {
					Write-ColorText "🔄 Mencoba argumen: $arg" -Color $Colors.Info
					$proc = Start-Process $targetFile -ArgumentList $arg -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
					if ($proc -and $proc.ExitCode -eq 0) {
						$method = "EXE Silent ($arg)"
						break
					}
				} catch {
					Write-LogEntry ("Failed with arg " + $arg + ": " + $_.Exception.Message) "WARNING"
					continue
				}
			}
			
			if (-not $proc) {
				$method = 'EXE Silent (fallback)'
				$proc = Start-Process $targetFile -ArgumentList "/S" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
			}
			$exitCode = if ($proc) { $proc.ExitCode } else { 0 }
		} else {
			# Coba asumsikan MSI jika tidak diketahui
			$method = 'Assumed MSI Silent (/qn)'
			Write-ColorText "📦 Menggunakan MSI installer (asumsi)" -Color $Colors.Info
			$proc = Start-Process msiexec.exe -ArgumentList "/i `"$targetFile`" /qn /norestart" -PassThru -Wait -WindowStyle Hidden
			$exitCode = $proc.ExitCode
		}
		
		Start-Sleep -Seconds 2  # Reduced delay untuk stabilitas
		
		# Verifikasi instalasi
		Write-ColorText "🔍 Memverifikasi instalasi..." -Color $Colors.Info
		$verifyResult = Test-CloudflareWARPInstalled
		
		if ($verifyResult.Installed) {
			Write-ColorText "✅ Instalasi berhasil!" -Color $Colors.Success
			Write-ColorText "📁 Lokasi: $($verifyResult.Path)" -Color $Colors.Success
			Write-ColorText "📋 Versi: $($verifyResult.Version)" -Color $Colors.Success
			
			# Auto-connect WARP VPN setelah instalasi berhasil
			Write-ColorText "🚀 Memulai WARP VPN..." -Color $Colors.Info
			$warpConnection = Start-CloudflareWARP
			
			if ($warpConnection.Connected) {
				Write-ColorText "🎉 WARP VPN berhasil dijalankan dan tersambung!" -Color $Colors.Success
			} else {
				Write-ColorText "⚠️ WARP terinstall tapi gagal tersambung" -Color $Colors.Warning
			}
			
			# Simpan hasil koneksi VPN untuk report
			$vpnResult = $warpConnection
		} else {
			Write-ColorText "⚠️ Instalasi selesai tapi verifikasi gagal" -Color $Colors.Warning
		}
		
		Write-LogEntry "WARP installer finished method=$method exitCode=$exitCode, Verified=$($verifyResult.Installed)" "INFO"
	} catch {
		Write-ColorText "❌ Error saat instalasi: $($_.Exception.Message)" -Color $Colors.Error
		Write-LogEntry "Error running WARP installer: $($_.Exception.Message)" "ERROR"
		return @{ Installed = $false; Method = $method; File = $targetFile; ExitCode = -2 }
	}
	
	# Smooth transition dari banner ke tampilan normal (tanpa Clear-Host yang kasar)
	Write-Host ""
	Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
	Write-ColorText "🎯 INSTALASI WARP SELESAI - TRANSISI KE AUTO-CONNECT" -Color $Colors.Success
	Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
	Write-Host ""
	return @{ 
		Installed = ($exitCode -eq 0); 
		Method = $method; 
		File = $targetFile; 
		ExitCode = $exitCode;
		VPNConnection = if ($verifyResult.Installed -and $vpnResult) { $vpnResult } else { $null }
	}
}

function Invoke-NetworkSafePacket {
	param([switch]$YesToAll)
	Write-LogEntry "Starting Network Safe Packet" "INFO"
	Write-ColorText "🚀 Menjalankan paket perbaikan jaringan yang aman..." -Color $Colors.Header

	$results = [ordered]@{}

	# Flush DNS
	try {
		Write-ColorText "🧹 Membersihkan cache DNS..." -Color $Colors.Info
		$proc = Start-Process ipconfig -ArgumentList "/flushdns" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
		$results.FlushDNS = if ($proc) { $proc.ExitCode } else { 0 }
		Write-LogEntry "ipconfig /flushdns exitCode=$($results.FlushDNS)" "INFO"
		Write-ColorText "✅ DNS cache berhasil dibersihkan" -Color $Colors.Success
		Start-Sleep -Seconds 1  # Delay untuk stabilitas
	} catch { $results.FlushDNS = -1; Write-LogEntry "Failed to flush DNS: $($_.Exception.Message)" "ERROR" }

	# Release & Renew IP (untuk reset koneksi jaringan)
	try {
		Write-ColorText "🔄 Melepas dan memperbarui IP address..." -Color $Colors.Info
		$proc = Start-Process ipconfig -ArgumentList "/release" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
		$results.ReleaseIP = if ($proc) { $proc.ExitCode } else { 0 }
		Write-LogEntry "ipconfig /release exitCode=$($results.ReleaseIP)" "INFO"
		Write-ColorText "✅ IP address berhasil dilepas" -Color $Colors.Success
		
		Start-Sleep -Seconds 3  # Tunggu lebih lama untuk stabilitas
		
		$proc = Start-Process ipconfig -ArgumentList "/renew" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
		$results.RenewIP = if ($proc) { $proc.ExitCode } else { 0 }
		Write-LogEntry "ipconfig /renew exitCode=$($results.RenewIP)" "INFO"
		Write-ColorText "✅ IP address berhasil diperbarui" -Color $Colors.Success
		Start-Sleep -Seconds 2  # Delay untuk stabilitas
	} catch { 
		$results.ReleaseIP = -1; $results.RenewIP = -1
		Write-LogEntry "Failed to release/renew IP: $($_.Exception.Message)" "ERROR" 
	}

	# Reset WinHTTP proxy (aman)
	try {
		Write-ColorText "🔧 Mereset WinHTTP proxy..." -Color $Colors.Info
		$proc = Start-Process netsh -ArgumentList "winhttp reset proxy" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
		$results.ResetWinHttpProxy = if ($proc) { $proc.ExitCode } else { 0 }
		Write-LogEntry "netsh winhttp reset proxy exitCode=$($results.ResetWinHttpProxy)" "INFO"
		Write-ColorText "✅ WinHTTP proxy berhasil direset" -Color $Colors.Success
		Start-Sleep -Seconds 1  # Delay untuk stabilitas
	} catch { $results.ResetWinHttpProxy = -1; Write-LogEntry "Failed to reset WinHTTP proxy: $($_.Exception.Message)" "ERROR" }

	# Optional: Winsock reset (but ask first, karena perlu restart)
	$results.WinsockReset = $null
	try {
		$ans = if ($YesToAll) { 'Yes' } else { Confirm-ActionEx "Reset Winsock (rekomendasi, tidak berisiko, memerlukan restart)?" }
		if ($ans -eq 'Yes') {
			Write-ColorText "🔧 Mereset Winsock..." -Color $Colors.Info
			$proc = Start-Process netsh -ArgumentList "winsock reset" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
			$results.WinsockReset = if ($proc) { $proc.ExitCode } else { 0 }
			Write-LogEntry "netsh winsock reset exitCode=$($results.WinsockReset)" "INFO"
			Write-ColorText "✅ Winsock berhasil direset" -Color $Colors.Success
			Write-ColorText "ℹ️ Perubahan Winsock akan berlaku setelah restart. Disarankan untuk me-restart perangkat." -Color $Colors.Warning
			Start-Sleep -Seconds 2  # Delay untuk stabilitas
		} else { $results.WinsockReset = 'Skipped' }
	} catch { $results.WinsockReset = -1; Write-LogEntry "Failed to reset Winsock: $($_.Exception.Message)" "ERROR" }

	# Cek port 5051
	Write-ColorText "🔍 Memeriksa penggunaan port 5051..." -Color $Colors.Info
	$portUsage = Get-Port5051Usage
	$results.Port5051 = $portUsage
	Start-Sleep -Seconds 1  # Delay untuk stabilitas

	# Bersihkan cache Roblox dengan backup
	Write-ColorText "🧹 Membersihkan cache Roblox (dengan backup)..." -Color $Colors.Info
	$results.CacheCleaned = Clear-RobloxCacheWithBackup

	return $results
}

function Show-NetworkPacketReport {
	param($PacketResults, $WarpInstallResult, $ConflictingApps)
	
	Write-ColorText "`n📋 LAPORAN PERBAIKAN JARINGAN & STABILITAS" -Color $Colors.Header
	Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
	
	if ($PacketResults) {
		Write-ColorText "• Flush DNS: $($PacketResults.FlushDNS)" -Color $Colors.Info
		Write-LogEntry ("Report: FlushDNS=" + $PacketResults.FlushDNS) "INFO"
		Write-ColorText "• Release IP: $($PacketResults.ReleaseIP)" -Color $Colors.Info
		Write-LogEntry ("Report: ReleaseIP=" + $PacketResults.ReleaseIP) "INFO"
		Write-ColorText "• Renew IP: $($PacketResults.RenewIP)" -Color $Colors.Info
		Write-LogEntry ("Report: RenewIP=" + $PacketResults.RenewIP) "INFO"
		Write-ColorText "• Reset WinHTTP Proxy: $($PacketResults.ResetWinHTTPProxy)" -Color $Colors.Info
		Write-LogEntry ("Report: ResetWinHTTPProxy=" + $PacketResults.ResetWinHTTPProxy) "INFO"
		Write-ColorText "• Winsock Reset: $($PacketResults.WinsockReset)" -Color $Colors.Info
		Write-LogEntry ("Report: WinsockReset=" + $PacketResults.WinsockReset) "INFO"
		Write-ColorText "• Cache Roblox dibersihkan (lokasi): $($PacketResults.CacheCleaned)" -Color $Colors.Info
		Write-LogEntry ("Report: CacheCleanedLocations=" + $PacketResults.CacheCleaned) "INFO"
	}
	
	if ($WarpInstallResult) {
		$warpStatus = if ($WarpInstallResult.Installed) { 'Terpasang' } else { 'Gagal/Skip' }
		Write-ColorText "• Cloudflare WARP: $warpStatus (method=$($WarpInstallResult.Method), code=$($WarpInstallResult.ExitCode))" -Color $Colors.Info
		Write-LogEntry ("Report: WARP status=" + $warpStatus + ", method=" + $WarpInstallResult.Method + ", code=" + $WarpInstallResult.ExitCode) "INFO"
		
		# Tambahkan info WARP VPN jika ada
		if ($WarpInstallResult.VPNConnection) {
			$vpnStatus = if ($WarpInstallResult.VPNConnection.Connected) { 'Tersambung' } else { 'Gagal' }
			$vpnColor = if ($WarpInstallResult.VPNConnection.Connected) { $Colors.Success } else { $Colors.Warning }
			Write-ColorText "• WARP VPN: $vpnStatus (PID=$($WarpInstallResult.VPNConnection.PID), Service=$($WarpInstallResult.VPNConnection.Service))" -Color $vpnColor
			Write-LogEntry ("Report: WARP VPN=" + $vpnStatus + ", PID=" + $WarpInstallResult.VPNConnection.PID + ", Service=" + $WarpInstallResult.VPNConnection.Service) "INFO"
		}
	}
	
	Write-ColorText "`n🔎 Port 5051" -Color $Colors.Header
	Write-ColorText "═══════════" -Color $Colors.Header
	if ($PacketResults -and $PacketResults.Port5051 -and $PacketResults.Port5051.Count -gt 0) {
		foreach ($i in $PacketResults.Port5051) {
			Write-ColorText ("• PID $($i.PID) - $($i.ProcessName) " + (if ($i.MainModule) { "($($i.MainModule))" } else { "" })) -Color $Colors.Warning
			Write-LogEntry "Port5051 in use by PID=$($i.PID) Name=$($i.ProcessName) Path=$($i.MainModule)" "INFO"
		}
		Write-LogEntry ("Report: Port5051Count=" + $PacketResults.Port5051.Count) "INFO"
	} else {
		Write-ColorText "• Tidak ada proses yang menggunakan port 5051" -Color $Colors.Success
		Write-LogEntry "Report: Port5051Count=0" "INFO"
	}
	
	Write-ColorText "`n🧪 Deteksi Aplikasi Berpotensi Konflik (Hyperion/Anti-cheat)" -Color $Colors.Header
	Write-ColorText "═══════════════════════════════════════════════════════════════" -Color $Colors.Header
	if ($ConflictingApps) {
		if ($ConflictingApps.RunningProcesses.Count -gt 0) {
			Write-ColorText "• Proses berjalan:" -Color $Colors.Warning
			foreach ($p in $ConflictingApps.RunningProcesses | Sort-Object Name -Unique) {
				Write-ColorText ("   - $($p.Name) (PID $($p.Id))") -Color $Colors.Info
				Write-LogEntry "Conflict process: $($p.Name) PID=$($p.Id)" "WARNING"
			}
			$names = ($ConflictingApps.RunningProcesses | Select-Object -ExpandProperty Name | Sort-Object -Unique)
			try { $namesJoined = ($names -join ',') } catch { $namesJoined = ($names | Out-String).Trim() }
			Write-LogEntry ("Report: ConflictRunningProcesses=" + $namesJoined) "INFO"
		} else { Write-ColorText "• Tidak ada proses konflik yang terdeteksi saat ini" -Color $Colors.Success }
		
		if ($ConflictingApps.InstalledApps.Count -gt 0) {
			Write-ColorText "• Aplikasi terinstal terkait:" -Color $Colors.Warning
			foreach ($a in $ConflictingApps.InstalledApps | Sort-Object Name -Unique) {
				Write-ColorText ("   - $($a.Name) $($a.Version)") -Color $Colors.Info
			}
			Write-LogEntry ("Report: ConflictInstalledAppsCount=" + $ConflictingApps.InstalledApps.Count) "INFO"
		}
		if ($ConflictingApps.Services.Count -gt 0) {
			Write-ColorText "• Services terkait:" -Color $Colors.Warning
			foreach ($s in $ConflictingApps.Services | Sort-Object Name -Unique) {
				Write-ColorText ("   - $($s.Name) ($($s.Status))") -Color $Colors.Info
			}
			Write-LogEntry ("Report: ConflictServicesCount=" + $ConflictingApps.Services.Count) "INFO"
		}
	}
	
	Write-ColorText "`nℹ️ Catatan: Banyak kasus Roblox menutup sendiri (wait result 258) karena hooking/driver dari Logitech G HUB/steering wheel, RTSS/MSI Afterburner, atau Crucial Momentum Cache. Nonaktifkan/keluarkan aplikasi tersebut saat bermain untuk stabilitas." -Color $Colors.Warning
}

function Invoke-NetworkAndStabilityFix {
	# Clean header tanpa Clear-Host untuk menghindari artifact
	Write-Host ""
	Write-ColorText "🔧 MEMULAI: Perbaikan Jaringan Aman + WARP + Cek Konflik" -Color $Colors.Header
	Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
	Write-Host ""

	# Pilih mode: Yes to all atau Step-by-step
	Write-ColorText "Pilih mode (A=Yes to all / S=Step-by-step): " -Color $Colors.Warning -NoNewLine
	$mode = ''
	do {
		$resp = Read-Host
		if ($resp -match '^[AaSs]$') { $mode = if ($resp -match '^[Aa]$') { 'All' } else { 'Step' } }
		else { Write-ColorText "❌ Jawab dengan A atau S: " -Color $Colors.Error -NoNewLine }
	} while (-not $mode)

	$packet = $null
	$warp = $null
	$conflicts = $null

	if ($mode -eq 'All') {
		# Jalankan semua tanpa konfirmasi tambahan
		Write-Host ""
		Write-ColorText "🚀 MODE: Yes to All - Menjalankan semua proses otomatis" -Color $Colors.Success
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		Write-Host ""
		
		$packet = Invoke-NetworkSafePacket -YesToAll
		$warp = Install-CloudflareWARP
		$conflicts = Find-ConflictingApps
	} else {
		# Step-by-step: konfirmasi tiap proses
		Write-Host ""
		Write-ColorText "🔍 MODE: Step-by-step - Konfirmasi setiap proses" -Color $Colors.Info
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		Write-Host ""
		
		$packet = [ordered]@{ FlushDNS=$null; ResetWinHttpProxy=$null; WinsockReset=$null; CacheCleaned=0; Port5051=@() }

		# Flush DNS
		Write-ColorText "🔧 PROSES 1: Flush DNS Cache" -Color $Colors.Header
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		$ans = Confirm-ActionEx "Jalankan ipconfig /flushdns?"
		if ($ans -eq 'Yes') {
			try { $p = Start-Process ipconfig -ArgumentList "/flushdns" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue; $packet.FlushDNS = if ($p){$p.ExitCode}else{0} } catch { $packet.FlushDNS = -1 }
			Write-LogEntry "Step FlushDNS exitCode=$($packet.FlushDNS)" "INFO"
		} else { $packet.FlushDNS = 'Skipped' }

		# Reset WinHTTP proxy
		Write-Host ""
		Write-ColorText "🔧 PROSES 2: Reset WinHTTP Proxy" -Color $Colors.Header
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		$ans = Confirm-ActionEx "Reset WinHTTP proxy (netsh winhttp reset proxy)?"
		if ($ans -eq 'Yes') {
			try { $p = Start-Process netsh -ArgumentList "winhttp reset proxy" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue; $packet.ResetWinHttpProxy = if ($p){$p.ExitCode}else{0} } catch { $packet.ResetWinHttpProxy = -1 }
			Write-LogEntry "Step ResetWinHttpProxy exitCode=$($packet.ResetWinHttpProxy)" "INFO"
		} else { $packet.ResetWinHttpProxy = 'Skipped' }

		# Winsock reset
		Write-Host ""
		Write-ColorText "🔧 PROSES 3: Reset Winsock" -Color $Colors.Header
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		$ans = Confirm-ActionEx "Reset Winsock (butuh restart setelahnya)?"
		if ($ans -eq 'Yes') {
			try { $p = Start-Process netsh -ArgumentList "winsock reset" -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue; $packet.WinsockReset = if ($p){$p.ExitCode}else{0} } catch { $packet.WinsockReset = -1 }
			Write-LogEntry "Step WinsockReset exitCode=$($packet.WinsockReset)" "INFO"
			Write-ColorText "ℹ️ Perubahan Winsock akan berlaku setelah restart. Disarankan untuk me-restart perangkat." -Color $Colors.Warning
		} else { $packet.WinsockReset = 'Skipped' }

		# Clean cache dengan backup
		Write-Host ""
		Write-ColorText "🔧 PROSES 4: Clean Cache Roblox" -Color $Colors.Header
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		$ans = Confirm-ActionEx "Bersihkan cache Roblox dengan backup?"
		if ($ans -eq 'Yes') { $packet.CacheCleaned = Clear-RobloxCacheWithBackup } else { $packet.CacheCleaned = 0 }

		# Cek port 5051
		Write-Host ""
		Write-ColorText "🔧 PROSES 5: Cek Port 5051" -Color $Colors.Header
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		$ans = Confirm-ActionEx "Cek port 5051 dan proses yang memakainya?"
		if ($ans -eq 'Yes') { $packet.Port5051 = Get-Port5051Usage } else { $packet.Port5051 = @() }

		# Install WARP
		Write-Host ""
		Write-ColorText "🔧 PROSES 6: Install Cloudflare WARP" -Color $Colors.Header
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		$ans = Confirm-ActionEx "Install Cloudflare WARP (1.1.1.1)?"
		if ($ans -eq 'Yes') { $warp = Install-CloudflareWARP } else { $warp = @{ Installed = $false; Method = 'Skipped'; File = $null; ExitCode = $null } }

		# Jalankan WARP VPN (jika WARP terinstall)
		if ($warp.Installed) {
			Write-Host ""
			Write-ColorText "🔧 PROSES 7: Auto-Connect WARP VPN" -Color $Colors.Header
			Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
			$ans = Confirm-ActionEx "Jalankan WARP VPN (auto-connect)?"
			if ($ans -eq 'Yes') { 
				$warpConnection = Start-CloudflareWARP
				$warp.VPNConnection = $warpConnection
			} else { 
				$warp.VPNConnection = $null 
			}
		}

		# Deteksi aplikasi konflik
		Write-Host ""
		Write-ColorText "🔧 PROSES 8: Deteksi Aplikasi Konflik" -Color $Colors.Header
		Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
		$ans = Confirm-ActionEx "Jalankan deteksi aplikasi konflik (G HUB/RTSS/Afterburner/Crucial)?"
		if ($ans -eq 'Yes') { $conflicts = Find-ConflictingApps } else { $conflicts = @{ RunningProcesses=@(); InstalledApps=@(); Services=@() } }
	}

	# Tampilkan report final
	Write-Host ""
	Write-ColorText "📋 LAPORAN FINAL: Perbaikan Jaringan & Stabilitas" -Color $Colors.Header
	Write-ColorText "══════════════════════════════════════════════════════════════" -Color $Colors.Header
	Write-Host ""
	
	Show-NetworkPacketReport -PacketResults $packet -WarpInstallResult $warp -ConflictingApps $conflicts
}

# Fungsi-fungsi ini sudah tidak digunakan karena digabung dalam Invoke-NetworkAndStabilityFix
# Dihapus untuk menghindari duplikasi dan confusion

# ==================== REPORT FUNCTIONS ====================

function Show-SystemReport {
    param($SystemInfo, $RobloxInfo, $Requirements, $LogInfo, $Connectivity)
    
    Write-ColorText "`n📋 LAPORAN SISTEM" -Color $Colors.Header
    Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
    try {
        $os = if ($SystemInfo) { $SystemInfo.OSName } else { $null }
        $gpu = if ($SystemInfo) { $SystemInfo.GPUName } else { $null }
        $ver = if ($RobloxInfo) { $RobloxInfo.Version } else { $null }
        Write-LogEntry ("SystemReport: OS='" + $os + "' GPU='" + $gpu + "' RobloxVersion='" + $ver + "'") "INFO"
    } catch {}
    
    if ($SystemInfo) {
        Write-ColorText "🖥️  Sistem Operasi: " -Color $Colors.Info -NoNewLine
        Write-ColorText $SystemInfo.OSName -Color $Colors.Accent
        Write-ColorText "🏗️  Arsitektur: " -Color $Colors.Info -NoNewLine
        Write-ColorText $SystemInfo.OSArchitecture -Color $Colors.Accent
        Write-ColorText "🧠 Prosesor: " -Color $Colors.Info -NoNewLine
        Write-ColorText $SystemInfo.CPUName -Color $Colors.Accent
        Write-ColorText "💾 RAM: " -Color $Colors.Info -NoNewLine
        Write-ColorText "$($SystemInfo.RAMSize) GB" -Color $Colors.Accent
        Write-ColorText "🎮 GPU: " -Color $Colors.Info -NoNewLine
        Write-ColorText $SystemInfo.GPUName -Color $Colors.Accent
        Write-ColorText "⚡ PowerShell: " -Color $Colors.Info -NoNewLine
        Write-ColorText $SystemInfo.PowerShellVersion -Color $Colors.Accent
    }
    Start-ReportDelay
    
    Write-ColorText "`n🎮 STATUS ROBLOX" -Color $Colors.Header
    Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
    
    if ($RobloxInfo.IsInstalled) {
        Write-ColorText "✅ Status: Terinstall" -Color $Colors.Success
        Write-ColorText "📁 Lokasi: $($RobloxInfo.InstallPath)" -Color $Colors.Info
        if ($RobloxInfo.ExecutablePath) { Write-ColorText "📄 Executable: $(Split-Path $RobloxInfo.ExecutablePath -Leaf)" -Color $Colors.Info }
        if ($RobloxInfo.Version) { Write-ColorText "🔖 Versi: $($RobloxInfo.Version)" -Color $Colors.Info }
        Write-ColorText "📊 Ukuran: $($RobloxInfo.Size) MB" -Color $Colors.Info
        if ($RobloxInfo.InstallDate) { Write-ColorText "📅 Install: $($RobloxInfo.InstallDate)" -Color $Colors.Info }
        if ($RobloxInfo.ExecHealth) {
            Write-ColorText "🔒 Kesehatan Executable: $($RobloxInfo.ExecHealth.Health)" -Color $Colors.Info
            Write-ColorText "   Tanda Tangan: $($RobloxInfo.ExecHealth.SignatureStatus)" -Color $Colors.Info
        }
        if ($RobloxInfo.IsRunning) { Write-ColorText "🟢 Status: Berjalan ($($RobloxInfo.ProcessCount) proses)" -Color $Colors.Success } else { Write-ColorText "🔴 Status: Tidak berjalan" -Color $Colors.Error }
    } else {
        Write-ColorText "❌ Status: Tidak terinstall" -Color $Colors.Error
    }
    Start-ReportDelay
    
    Write-ColorText "`n✅ PERSYARATAN SISTEM" -Color $Colors.Header
    Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
    foreach ($req in $Requirements.GetEnumerator()) {
        $met = if ($req.Value.Met) { "✅" } else { "❌" }
        $color = if ($req.Value.Met) { $Colors.Success } else { $Colors.Error }
        Write-ColorText "$met $($req.Key): " -Color $color -NoNewLine
        Write-ColorText "$($req.Value.Current)" -Color $Colors.Info
        Write-ColorText "   Diperlukan: $($req.Value.Required)" -Color $Colors.Info
    }
    Start-ReportDelay

    # Konektivitas
    if ($Connectivity) {
        Write-ColorText "`n🌐 KONEKTIVITAS ROBLOX" -Color $Colors.Header
        Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
        $pingStatus = if ($Connectivity.PingOk) { 'OK' } else { 'Gagal' }
        $mainStatus = if ($Connectivity.HttpOkMain) { 'OK' } else { 'Gagal' }
        $apiStatus  = if ($Connectivity.HttpOkApi)  { 'OK' } else { 'Gagal' }
        Write-ColorText ("Ping roblox.com: $pingStatus") -Color $Colors.Info
        Write-ColorText ("HTTP www.roblox.com: $mainStatus") -Color $Colors.Info
        Write-ColorText ("HTTP apis.roblox.com: $apiStatus") -Color $Colors.Info
        try { Write-LogEntry ("ConnectivityReport: Ping=" + $Connectivity.PingOk + ", Main=" + $Connectivity.HttpOkMain + ", Api=" + $Connectivity.HttpOkApi) "INFO" } catch {}
    }
    
    if ($LogInfo.Found) {
        try {
            $desktopPath = [Environment]::GetFolderPath('Desktop')
            $desktopLogs = (Resolve-Path (Join-Path $desktopPath 'logschecker') -ErrorAction SilentlyContinue).Path
            if (-not $desktopLogs) { $desktopLogs = (Resolve-Path $script:LogPath -ErrorAction SilentlyContinue).Path }
        } catch { $desktopLogs = $script:LogPath }
        Write-ColorText "`n📄 LOG ROBLOX" -Color $Colors.Header
        Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
        Write-ColorText "📁 Ditemukan: $($LogInfo.LogPaths.Count) file log" -Color $Colors.Success
        Write-ColorText "📂 Lokasi log (Ctrl+Click):" -Color $Colors.Info
        Write-Host $desktopLogs
        if ($LogInfo.ErrorSummary.Count -gt 0) {
            Write-ColorText "🔎 Cuplikan Error/Crash (maks 3):" -Color $Colors.Warning
            $preview = [Math]::Min(3, $LogInfo.ErrorSummary.Count)
            for ($i=0; $i -lt $preview; $i++) { Write-ColorText ("   • " + $LogInfo.ErrorSummary[$i]) -Color $Colors.Info }
        }
    }
}

function Show-DiagnosisReport {
    param($IntegrityIssues, $CommonIssues, $LogInfo)
    
    Write-ColorText "`n🔍 HASIL DIAGNOSIS" -Color $Colors.Header
    Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
    
    $totalIssues = $IntegrityIssues.Count + $CommonIssues.Count
    
    if ($totalIssues -eq 0 -and $LogInfo.ErrorSummary.Count -eq 0) {
        Write-ColorText "✅ Tidak ditemukan masalah!" -Color $Colors.Success
        Write-ColorText "   Roblox seharusnya berjalan dengan normal." -Color $Colors.Info
        Write-LogEntry "DiagnosisReport: No issues found" "INFO"
        return $false
    }
    Start-ReportDelay
    
    Write-ColorText "⚠️ Ditemukan $totalIssues masalah:" -Color $Colors.Warning
    
    if ($IntegrityIssues.Count -gt 0) {
        Write-ColorText "`n🔧 Masalah Integritas:" -Color $Colors.Error
        foreach ($issue in $IntegrityIssues) {
            Write-ColorText "   • $issue" -Color $Colors.Error
        }
        Write-LogEntry ("DiagnosisReport: IntegrityIssuesCount=" + $IntegrityIssues.Count) "INFO"
        Start-ReportDelay
    }
    if ($CommonIssues.Count -gt 0) {
        Write-ColorText "`n⚠️ Masalah Umum:" -Color $Colors.Warning
        foreach ($issue in $CommonIssues) {
            Write-ColorText "   • $issue" -Color $Colors.Warning
        }
        Write-LogEntry ("DiagnosisReport: CommonIssuesCount=" + $CommonIssues.Count) "INFO"
        Start-ReportDelay
    }
    if ($LogInfo.ErrorSummary.Count -gt 0) {
        Write-ColorText "`n🚨 Ringkasan Error/Crash dari Log Roblox:" -Color $Colors.Error
        $maxShow = [Math]::Min(5, $LogInfo.ErrorSummary.Count)
        for ($i=0; $i -lt $maxShow; $i++) {
            Write-ColorText "   • $($LogInfo.ErrorSummary[$i])" -Color $Colors.Error
        }
        Write-LogEntry ("DiagnosisReport: ErrorSummaryShown=" + $maxShow + "/" + $LogInfo.ErrorSummary.Count) "INFO"
        if ($LogInfo.ErrorSummary.Count -gt $maxShow) {
            Write-ColorText "   ...dan $($LogInfo.ErrorSummary.Count - $maxShow) error/crash lain. Lihat log lengkap di folder log." -Color $Colors.Warning
        }
    }
    return $true
}

function Show-RepairSummary {
    param($RepairResults)
    
    Write-ColorText "`n🔨 HASIL PERBAIKAN" -Color $Colors.Header
    Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
    try { Write-LogEntry ("RepairSummary: " + ($RepairResults | ConvertTo-Json -Compress)) "INFO" } catch {}
    
    $totalFixed = 0
    foreach ($result in $RepairResults.GetEnumerator()) {
        if ($result.Value -gt 0) {
            Write-ColorText "✅ $($result.Key): $($result.Value) diperbaiki" -Color $Colors.Success
            $totalFixed += $result.Value
        } else {
            Write-ColorText "ℹ️ $($result.Key): Tidak ada yang perlu diperbaiki" -Color $Colors.Info
        }
    }
    
    if ($totalFixed -gt 0) {
        Write-ColorText "`n🎉 Total $totalFixed masalah berhasil diperbaiki!" -Color $Colors.Success
        Write-ColorText "💡 Silakan coba jalankan Roblox lagi." -Color $Colors.Info
    } else {
        Write-ColorText "`n❓ Tidak ada perbaikan yang diperlukan." -Color $Colors.Info
        Write-ColorText "💡 Jika masalah masih ada, coba restart komputer atau install ulang Roblox." -Color $Colors.Warning
    }
}

# ==================== ADMIN & SECURITY FUNCTIONS ====================

function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-AdminRights {
    if (Test-IsAdmin) {
        return $true
    }
    
    Write-ColorText "⚠️ Beberapa perbaikan memerlukan hak administrator." -Color $Colors.Warning
    Write-ColorText "💡 Script akan melanjutkan dengan perbaikan yang tidak memerlukan admin." -Color $Colors.Info
    
    return $false
}

function Set-ExecutionPolicyTemporary {
    try {
        $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
        try {
            Write-LogEntry "Current execution policy: $currentPolicy" "INFO"
        } catch {
            # Silent fallback for logging
        }
        
        if ($currentPolicy -eq "Restricted") {
            try {
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
                try {
                    Write-LogEntry "Execution policy temporarily changed to RemoteSigned" "INFO"
                } catch {
                    # Silent fallback for logging
                }
                return $currentPolicy
            } catch {
                try {
                    Write-LogEntry "Could not change execution policy: $($_.Exception.Message)" "WARNING"
                } catch {
                    # Silent fallback for logging
                }
            }
        }
    } catch {
        try {
            Write-LogEntry "Could not check execution policy: $($_.Exception.Message)" "WARNING"
        } catch {
            # Silent fallback for logging
        }
    }
    return $null
}

function Restore-ExecutionPolicy {
    param($OriginalPolicy)
    
    if ($OriginalPolicy -and $OriginalPolicy -eq "Restricted") {
        try {
            Set-ExecutionPolicy -ExecutionPolicy $OriginalPolicy -Scope CurrentUser -Force -ErrorAction SilentlyContinue
            try {
                Write-LogEntry "Execution policy restored to: $OriginalPolicy" "INFO"
            } catch {
                # Silent fallback for logging
            }
        } catch {
            try {
                Write-LogEntry "Could not restore execution policy: $($_.Exception.Message)" "WARNING"
            } catch {
                # Silent fallback for logging
            }
        }
    }
}

# ==================== CLEANUP FUNCTIONS ====================

function Invoke-SafetyCleanup {
    Write-LogEntry "Starting safety cleanup" "INFO"
    
    if (-not $NoCleanup) {
        # Clean temporary files
        foreach ($tempFile in $Global:TempFiles) {
            if (Test-Path $tempFile) {
                try {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    Write-LogEntry "Cleaned temp file: $tempFile" "DEBUG"
                } catch {
                    Write-LogEntry "Could not clean temp file $tempFile`: $($_.Exception.Message)" "WARNING"
                }
            }
        }
        
        # Clean elevation temporary script
        $elevationTempScript = "$env:TEMP\RobloxChecker_Elevated.ps1"
        if (Test-Path $elevationTempScript) {
            try {
                Remove-Item $elevationTempScript -Force -ErrorAction SilentlyContinue
                Write-LogEntry "Cleaned elevation temp script: $elevationTempScript" "INFO"
            } catch {
                Write-LogEntry "Could not clean elevation temp script: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Clean remote execution temporary script
        $remoteTempScript = "$env:TEMP\RobloxChecker_Remote.ps1"
        if (Test-Path $remoteTempScript) {
            try {
                Remove-Item $remoteTempScript -Force -ErrorAction SilentlyContinue
                Write-LogEntry "Cleaned remote temp script: $remoteTempScript" "INFO"
            } catch {
                Write-LogEntry "Could not clean remote temp script: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Clean global temp script if exists
        if ($Global:TempScriptToCleanup -and (Test-Path $Global:TempScriptToCleanup)) {
            try {
                Remove-Item $Global:TempScriptToCleanup -Force -ErrorAction SilentlyContinue
                Write-LogEntry "Cleaned global temp script: $Global:TempScriptToCleanup" "INFO"
            } catch {
                Write-LogEntry "Could not clean global temp script: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Clean processes
        foreach ($processId in $Global:ProcessesToCleanup) {
            try {
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($process -and -not $process.HasExited) {
                    $process.CloseMainWindow()
                    Start-Sleep -Seconds 1
                    if (-not $process.HasExited) {
                        $process.Kill()
                    }
                    Write-LogEntry "Cleaned process: $processId" "DEBUG"
                }
            } catch {
                Write-LogEntry "Could not clean process $processId`: $($_.Exception.Message)" "WARNING"
            }
        }
    }
    
    Write-LogEntry "Safety cleanup completed" "INFO"
}

function Show-Goodbye {
	$computerName = $env:COMPUTERNAME
	Write-Host ""
	Write-ColorText "╔══════════════════════════════════════════════════════════════╗" -Color $Colors.Header
	Write-ColorText "║                                                              ║" -Color $Colors.Header
	Write-ColorText "║                   🎮 SELESAI! 🎮                            ║" -Color $Colors.Header
	Write-ColorText "║                                                              ║" -Color $Colors.Header
	Write-ColorText "║               Terima kasih $computerName!                    ║" -Color $Colors.Header
	Write-ColorText "║                                                              ║" -Color $Colors.Header
	Write-ColorText "╚══════════════════════════════════════════════════════════════╝" -Color $Colors.Header
	Write-Host ""
	Write-ColorText "📄 Log tersimpan di (Ctrl+Click):" -Color $Colors.Info
	Write-Host $Global:LogFile
	Write-ColorText "📂 Folder log (Ctrl+Click):" -Color $Colors.Info
	# Pastikan gunakan path aktual yang dipakai script
	try {
		$effectiveLogPath = (Resolve-Path $script:LogPath -ErrorAction SilentlyContinue).Path
		if (-not $effectiveLogPath) { $effectiveLogPath = $script:LogPath }
	} catch { $effectiveLogPath = $script:LogPath }
	Write-Host $effectiveLogPath
	Write-Host ""
	Write-ColorText "Sampai jumpa! 👋" -Color $Colors.Success
}

function Show-CountdownAndClose {
    param(
        [int]$Seconds = 5
    )
    
    Write-Host ""
    Write-ColorText "⏰ Program akan menutup dalam beberapa detik..." -Color $Colors.Warning
    
    for ($i = $Seconds; $i -gt 0; $i--) {
        Write-ColorText "`r🔄 Menutup dalam $i detik..." -Color $Colors.Accent -NoNewLine
        Start-Sleep -Seconds 1
    }
    
    Write-Host ""
    Write-ColorText "👋 Menutup program..." -Color $Colors.Success
    Write-LogEntry "Auto-closing terminal after $Seconds seconds countdown" "INFO"
    
    # Close the terminal window with improved methods
    try {
        $host.UI.RawUI.WindowTitle = "Roblox Checker - Closing..."
        Start-Sleep -Milliseconds 500
        
        # Method 1: Clean exit with proper cleanup
        try {
            # Ensure all cleanup is done
            if (Get-Variable -Name "Global:LogFile" -ErrorAction SilentlyContinue) {
                Write-LogEntry "Terminal closing initiated" "INFO"
            }
            
            # Graceful exit
            exit 0
        } catch {
            # Method 2: Force exit if graceful fails
            try {
                [Environment]::Exit(0)
            } catch {
                # Method 3: Last resort - force process termination
                try {
                    $currentProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
                    if ($currentProcess) {
                        $currentProcess.Kill()
                    }
                } catch {
                    # Method 4: Final fallback
                    Write-ColorText "💡 Tekan Enter untuk menutup manual..." -Color $Colors.Info
                    Read-Host | Out-Null
                    exit 0
                }
            }
        }
    } catch {
        Write-LogEntry "Failed to auto-close terminal: $($_.Exception.Message)" "WARNING"
        Write-ColorText "💡 Tekan Enter untuk menutup manual..." -Color $Colors.Info
        Read-Host | Out-Null
        exit 0
    }
}

function Show-DownloadProgress {
    param(
        [string]$Url,
        [string]$OutFile,
        [string]$Description = "Downloading"
    )
    
    try {
        Write-ColorText "📥 $Description..." -Color $Colors.Info
        Write-ColorText "🔗 URL: $Url" -Color $Colors.Accent
        
        # Get file size first (if possible)
        $totalBytes = 0
        try {
            $request = [System.Net.WebRequest]::Create($Url)
            $response = $request.GetResponse()
            $totalBytes = $response.ContentLength
            $response.Close()
        } catch {
            Write-LogEntry "Could not get file size: $($_.Exception.Message)" "WARNING"
        }
        
        # Start download in background
        $startTime = Get-Date
        $spinners = @('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')
        $counter = 0
        
        # Start download job
        $job = Start-Job -ScriptBlock {
            param($url, $outFile)
            try {
                Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing
                return "SUCCESS"
            } catch {
                return "ERROR: $($_.Exception.Message)"
            }
        } -ArgumentList $Url, $OutFile
        
        # Show progress while downloading
        while ($job.State -eq "Running") {
            $spinner = $spinners[$counter % $spinners.Length]
            $elapsed = (Get-Date) - $startTime
            $elapsedStr = "{0:mm\:ss}" -f $elapsed
            
            # Check if file exists and get current size
            $currentSize = 0
            if (Test-Path $OutFile) {
                $currentSize = (Get-Item $OutFile).Length
            }
            
            $currentKB = [math]::Round($currentSize / 1KB, 1)
            $totalKB = [math]::Round($totalBytes / 1KB, 1)
            
            if ($totalBytes -gt 0) {
                $percent = [math]::Round(($currentSize / $totalBytes) * 100)
                $progressBarLength = 20
                $filledLength = [math]::Floor($percent / 100 * $progressBarLength)
                $progressBar = "█" * $filledLength + "░" * ($progressBarLength - $filledLength)
                Write-ColorText "`r$spinner 📊 [$progressBar] $percent% ($currentKB KB / $totalKB KB) - $elapsedStr" -Color $Colors.Accent -NoNewLine
            } else {
                Write-ColorText "`r$spinner Downloading... ($currentKB KB) - $elapsedStr" -Color $Colors.Accent -NoNewLine
            }
            
            Start-Sleep -Milliseconds 200
            $counter++
        }
        
        # Get result
        $result = Receive-Job $job
        Remove-Job $job
        
        if ($result -eq "SUCCESS") {
            if (Test-Path $OutFile) {
                $fileSize = (Get-Item $OutFile).Length
                $fileSizeKB = [math]::Round($fileSize / 1KB, 1)
                Write-ColorText "`n✅ Download selesai! ($fileSizeKB KB)" -Color $Colors.Success
                return $true
            } else {
                Write-ColorText "`n❌ File tidak ditemukan setelah download" -Color $Colors.Error
                return $false
            }
        } else {
            Write-ColorText "`n❌ Download gagal: $result" -Color $Colors.Error
            return $false
        }
        
    } catch {
        Write-ColorText "❌ Error dalam download: $($_.Exception.Message)" -Color $Colors.Error
        return $false
    }
}

function Show-DownloadSpinner {
    param(
        [string]$Url,
        [string]$OutFile,
        [string]$Description = "Downloading"
    )
    
    Write-ColorText "📥 $Description..." -Color $Colors.Info
    Write-ColorText "🔗 URL: $Url" -Color $Colors.Accent
    
    $spinners = @('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')
    $counter = 0
    $startTime = Get-Date
    
    # Start download in background
    $job = Start-Job -ScriptBlock {
        param($url, $outFile)
        try {
            Invoke-WebRequest -Uri $url -OutFile $outFile -UseBasicParsing
            return "SUCCESS"
        } catch {
            return "ERROR: $($_.Exception.Message)"
        }
    } -ArgumentList $Url, $OutFile
    
    # Show spinner while downloading
    while ($job.State -eq "Running") {
        $spinner = $spinners[$counter % $spinners.Length]
        $elapsed = (Get-Date) - $startTime
        $elapsedStr = "{0:mm\:ss}" -f $elapsed
        
        Write-ColorText "`r$spinner Downloading... ($elapsedStr)" -Color $Colors.Accent -NoNewLine
        Start-Sleep -Milliseconds 100
        $counter++
    }
    
    # Get result
    $result = Receive-Job $job
    Remove-Job $job
    
    if ($result -eq "SUCCESS") {
        if (Test-Path $OutFile) {
            $fileSize = (Get-Item $OutFile).Length
            $fileSizeKB = [math]::Round($fileSize / 1KB, 1)
            Write-ColorText "`n✅ Download selesai! ($fileSizeKB KB)" -Color $Colors.Success
            return $true
        } else {
            Write-ColorText "`n❌ File tidak ditemukan setelah download" -Color $Colors.Error
            return $false
        }
    } else {
        Write-ColorText "`n❌ Download gagal: $result" -Color $Colors.Error
        return $false
    }
}

# ==================== INTERACTIVE FUNCTIONS ====================

function Reset-Header {
    try { Clear-Host; Show-Header; [Console]::SetCursorPosition(0, $Global:ContentStartY) } catch {}
}

function Show-ArrowMenu {
    param(
        [string[]]$Options,
        [int]$Default = 0
    )
    $selected = $Default
    $arrow = "➤"

    # Gambar sekali di awal
    Clear-Host
    Show-Header
    Write-Host "🎯 PILIHAN TINDAKAN" -ForegroundColor DarkYellow
    Write-Host "═══════════════════════════════════════" -ForegroundColor Gray
    # Simpan posisi awal baris opsi
    $optionsTopY = 0
    try { $optionsTopY = [Console]::CursorTop } catch { $optionsTopY = 0 }

    function Write-MenuOptions {
        param([int]$Sel)
        try { [Console]::SetCursorPosition(0, $optionsTopY) } catch {}
        for ($i=0; $i -lt $Options.Length; $i++) {
            if ($i -eq $Sel) {
                Write-Host ($arrow + " " + $Options[$i] + (" " * 40)) -ForegroundColor Black -BackgroundColor Yellow
            } else {
                Write-Host ("  " + $Options[$i] + (" " * 40)) -ForegroundColor DarkYellow
            }
        }
        Write-Host ""
        Write-Host "Gunakan panah atas/bawah, Enter untuk pilih." -ForegroundColor Gray
    }

    Write-MenuOptions -Sel $selected
    
    do {
        $key = $null
        try { $key = [System.Console]::ReadKey($true) } catch {}
        if ($key) {
            if ($key.Key -eq "UpArrow") { $selected = if ($selected -le 0) { $Options.Length-1 } else { $selected-1 }; Write-MenuOptions -Sel $selected }
            elseif ($key.Key -eq "DownArrow") { $selected = if ($selected -ge $Options.Length-1) { 0 } else { $selected+1 }; Write-MenuOptions -Sel $selected }
            elseif ($key.Key -eq "Enter") { return ($selected+1) }
        } else {
            try { [Console]::SetCursorPosition(0, ($optionsTopY + $Options.Length + 2)) } catch {}
            $userInput = Read-Host ("Pilihan Anda (1-" + $Options.Length + ")")
            if ($userInput -match ("^[1-" + $Options.Length + "]$")) { return [int]$userInput }
            Write-MenuOptions -Sel $selected
        }
    } while ($true)
}

# ==================== MAIN EXECUTION FUNCTIONS ====================

# Helper untuk jeda halus antar section laporan
function Start-ReportDelay {
    param([int]$Milliseconds = 800)
    Start-Sleep -Milliseconds $Milliseconds
}

# Helpers untuk layout agar header tetap persist
$Global:ContentStartY = 0
function Set-CursorToContentStart {
    try { [Console]::SetCursorPosition(0, $Global:ContentStartY) } catch {}
}
function Clear-ContentArea {
    try {
        $raw = $host.UI.RawUI
        $width = $raw.BufferSize.Width
        $height = $raw.BufferSize.Height
        $rect = New-Object System.Management.Automation.Host.Rectangle 0, $Global:ContentStartY, ($width - 1), ($height - 1)
        $raw.SetBufferContents($rect, ' ')
        [Console]::SetCursorPosition(0, $Global:ContentStartY)
    } catch {}
}
function Reset-ContentArea {
    Clear-ContentArea
    Set-CursorToContentStart
}

function Invoke-FullDiagnosis {
    Clear-Host
    Write-ColorText "🔍 MEMULAI DIAGNOSIS LENGKAP..." -Color $Colors.Header
    
    Show-LoadingBar -Text "Mengumpulkan informasi sistem" -Duration 2
    $systemInfo = Get-SystemInfo
    Show-LoadingBar -Text "Mendeteksi instalasi Roblox" -Duration 1
    $robloxInfo = Get-RobloxInfo
    Show-LoadingBar -Text "Memeriksa persyaratan sistem" -Duration 1
    $requirements = Test-SystemRequirements
    Show-LoadingBar -Text "Mengumpulkan log Roblox" -Duration 1
    $logInfo = Get-RobloxLogs
    Show-LoadingBar -Text "Mendiagnosis masalah" -Duration 2
    $integrityIssues = Test-RobloxIntegrity
    $commonIssues = Test-CommonIssues
    $connectivity = Test-RobloxConnectivity
    
    Show-SystemReport -SystemInfo $systemInfo -RobloxInfo $robloxInfo -Requirements $requirements -LogInfo $logInfo -Connectivity $connectivity
    Start-ReportDelay
    $hasIssues = Show-DiagnosisReport -IntegrityIssues $integrityIssues -CommonIssues $commonIssues -LogInfo $logInfo
    
    return @{ HasIssues = $hasIssues; IntegrityIssues = $integrityIssues; CommonIssues = $commonIssues; SystemInfo = $systemInfo; RobloxInfo = $robloxInfo }
}

# Tampilkan rencana perbaikan berdasarkan diagnosis
function Show-RepairPlan {
	param($DiagnosisResults, [bool]$IsAdmin)
	Write-ColorText "`n🧭 RENCANA PERBAIKAN" -Color $Colors.Header
	Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
	Write-ColorText "1) Tutup proses Roblox yang bermasalah" -Color $Colors.Info
	Write-ColorText "2) Bersihkan cache Roblox (aman)" -Color $Colors.Info
	if ($IsAdmin) { Write-ColorText "3) Perbaiki registry Roblox (memerlukan admin)" -Color $Colors.Info }
	Write-ColorText ("" + (if ($IsAdmin) { "4" } else { "3" }) + ") Cek & sarankan dependensi (.NET/VC++)") -Color $Colors.Info
}

# Pilih mode perbaikan
function Select-RepairMode {
	Write-ColorText "`nPilih mode perbaikan: (A=Ya untuk semua / S=Step-by-step / B=Batalkan): " -Color $Colors.Warning -NoNewLine
	do {
		$resp = Read-Host
		if ($resp -match '^[AaSsBb]$') {
			if ($resp -match '^[Aa]$') { return 'All' }
			if ($resp -match '^[Ss]$') { return 'Step' }
			return 'Cancel'
		} else {
			Write-ColorText "❌ Jawab dengan A, S, atau B: " -Color $Colors.Error -NoNewLine
		}
	} while ($true)
}

function Invoke-AutoRepair {
	param($DiagnosisResults)
	
	Write-ColorText "`n🔧 MEMULAI PERBAIKAN OTOMATIS..." -Color $Colors.Header
	Write-Host ""
	
	if (-not $DiagnosisResults.HasIssues) {
		Write-ColorText "ℹ️ Tidak ada masalah yang terdeteksi untuk diperbaiki." -Color $Colors.Info
		return
	}
	
	$isAdmin = Request-AdminRights
	$repairResults = @{}

	# Tampilkan rencana perbaikan dan pilih mode
	Show-RepairPlan -DiagnosisResults $DiagnosisResults -IsAdmin $isAdmin
	$mode = Select-RepairMode
	if ($mode -eq 'Cancel') { Write-ColorText "⏭️ Dibatalkan oleh pengguna." -Color $Colors.Warning; return }

	if ($mode -eq 'All') {
		# Jalankan semua langkah tanpa prompt per-langkah
		Show-LoadingBar -Text "Menutup proses bermasalah" -Duration 1
		$repairResults["Proses"] = Repair-RobloxProcesses
		Show-LoadingBar -Text "Membersihkan cache" -Duration 2
		$repairResults["Cache"] = Repair-RobloxCache
		if ($isAdmin) {
			Show-LoadingBar -Text "Memperbaiki registry" -Duration 1
			$regResult = Repair-RobloxRegistry
			$repairResults["Registry"] = if ($regResult) { 1 } else { 0 }
		} else { $repairResults["Registry"] = 0 }
		Show-LoadingBar -Text "Memeriksa dependensi" -Duration 1
		$repairResults["Dependensi"] = Install-MissingDependencies
	} else {
		# Step-by-step dengan Y/N/Skip
		$ans = Confirm-ActionEx "Tutup proses Roblox yang bermasalah?"; if ($ans -eq 'Yes') { Show-LoadingBar -Text "Menutup proses bermasalah" -Duration 1; $repairResults["Proses"] = Repair-RobloxProcesses } else { $repairResults["Proses"] = 0 }
		$ans = Confirm-ActionEx "Bersihkan cache Roblox?"; if ($ans -eq 'Yes') { Show-LoadingBar -Text "Membersihkan cache" -Duration 2; $repairResults["Cache"] = Repair-RobloxCache } else { $repairResults["Cache"] = 0 }
		if ($isAdmin) {
			$ans = Confirm-ActionEx "Perbaiki registry Roblox (memerlukan admin)?"; if ($ans -eq 'Yes') { Show-LoadingBar -Text "Memperbaiki registry" -Duration 1; $regResult = Repair-RobloxRegistry; $repairResults["Registry"] = if ($regResult) { 1 } else { 0 } } else { $repairResults["Registry"] = 0 }
		} else { $repairResults["Registry"] = 0 }
		$ans = Confirm-ActionEx "Cek dan sarankan dependensi (.NET/VC++)?"; if ($ans -eq 'Yes') { Show-LoadingBar -Text "Memeriksa dependensi" -Duration 1; $repairResults["Dependensi"] = Install-MissingDependencies } else { $repairResults["Dependensi"] = 0 }
	}
	
	Show-RepairSummary -RepairResults $repairResults
	Write-LogEntry "AutoRepair: started" "INFO"

	try {
		$fixed = 0
		foreach ($kv in $repairResults.GetEnumerator()) { if ($kv.Value -is [int]) { $fixed += [math]::Max(0, $kv.Value) } }
		Write-LogEntry ("AutoRepair: completed TotalFixed=" + $fixed + ", Detail=" + ($repairResults | ConvertTo-Json -Compress)) "INFO"
	} catch {}
}

function Invoke-CacheCleanOnly {
    Write-ColorText "`n🧹 MEMBERSIHKAN CACHE ROBLOX..." -Color $Colors.Header
    Write-Host ""
    
    Show-LoadingBar -Text "Membersihkan cache" -Duration 2
    $cleaned = Repair-RobloxCache
    
    if ($cleaned -gt 0) {
        Write-ColorText "✅ Cache berhasil dibersihkan!" -Color $Colors.Success
        Write-ColorText "💡 Silakan coba jalankan Roblox lagi." -Color $Colors.Info
    } else {
        Write-ColorText "ℹ️ Tidak ada cache yang perlu dibersihkan." -Color $Colors.Info
    }
}

# ==================== SIGNAL HANDLERS ====================

function Register-CleanupHandlers {
    # Register Ctrl+C handler - simplified and robust
    try {
        [Console]::TreatControlCAsInput = $false
    } catch {
        # Silent fallback if console control not available
    }
    
    # Register exit handler - simplified and robust
    try {
        $null = Register-ObjectEvent -InputObject ([System.AppDomain]::CurrentDomain) -EventName ProcessExit -Action {
            try {
                Invoke-SafetyCleanup
            } catch {
                # Silent fallback - don't break script execution
            }
        }
    } catch {
        # Silent fallback if event registration fails
        try {
            Write-LogEntry "Could not register cleanup handlers: $($_.Exception.Message)" "WARNING"
        } catch {
            # Silent fallback for logging too
        }
    }
}

# ==================== MAIN SCRIPT EXECUTION ====================

function Main {
	try {
		# Check admin privileges first - if not admin, exit immediately
		if (-not (Test-AdminPrivileges)) {
			Request-AdminElevation
			# If we reach here, script will exit; safeguard anyway
			exit 1
		}

		# Admin shell confirmed; if executed via irm|iex, download and run the script from temp
		Invoke-RemoteExecution

		Write-ColorText "✅ Berjalan dengan hak akses Administrator" -Color $Colors.Success
		
		# Initialize environment
		Initialize-Environment
		Register-CleanupHandlers
		$originalPolicy = Set-ExecutionPolicyTemporary
		try {
			Write-LogEntry "Main menu started" "INFO"
		} catch {
			Write-Host "⚠️ Logging error: $($_.Exception.Message)" -ForegroundColor Red
		}
		
		do {
			$menuOptions = @(
				"🔍 Diagnosis Lengkap (Recommended)",
				"🔧 Perbaikan Otomatis",
				"🧹 Bersihkan Cache Saja",
				"🛠️ Safe Net Packet + WARP + Cek Konflik",
				"❌ Keluar"
			)
			$choice = Show-ArrowMenu -Options $menuOptions
			
			switch ($choice) {
				1 { try { $diagnosisResults = Invoke-FullDiagnosis } catch { Write-ColorText "❌ Diagnosis gagal: $($_.Exception.Message)" -Color $Colors.Error } }
				2 {
					try {
						Clear-Host
						Write-ColorText "🔍 Menjalankan diagnosis cepat..." -Color $Colors.Info
						$diagnosisResults = Invoke-FullDiagnosis
						Invoke-AutoRepair -DiagnosisResults $diagnosisResults
					} catch { Write-ColorText "❌ Perbaikan gagal: $($_.Exception.Message)" -Color $Colors.Error }
				}
				3 { Clear-Host; Invoke-CacheCleanOnly }
				4 { try { Write-LogEntry "Launching NetworkAndStabilityFix" "INFO"; Invoke-NetworkAndStabilityFix } catch { Write-ColorText "❌ Gagal menjalankan paket jaringan: $($_.Exception.Message)" -Color $Colors.Error; Write-LogEntry ("NetworkAndStabilityFix failed: " + $_.Exception.Message) "ERROR" } }
				5 { break }
			}
			
			if ($choice -ne 5) {
				Write-Host ""
				Write-ColorText "Tekan Enter untuk kembali ke menu..." -Color $Colors.Accent
				Read-Host | Out-Null
			}
			
		} while ($choice -ne 5)
		Write-LogEntry "Main menu exited" "INFO"
		
	} catch {
		Write-LogEntry "Unexpected error in main execution: $($_.Exception.Message)" "ERROR"
		Write-ColorText "❌ Terjadi kesalahan tak terduga: $($_.Exception.Message)" -Color $Colors.Error
		Write-ColorText "📄 Periksa log file untuk detail: $Global:LogFile" -Color $Colors.Info
	} finally {
		# Animasi cleaning up sebelum keluar
		try {
			Write-ColorText "\n🧹 Membersihkan sisa-sisa sementara..." -Color $Colors.Header
			Show-LoadingSpinner -Text "Cleaning up" -Duration 2
		} catch {}
		Invoke-SafetyCleanup
		if ($originalPolicy) { Restore-ExecutionPolicy -OriginalPolicy $originalPolicy }
		Write-LogEntry "=== ROBLOX CHECKER SESSION ENDED ===" "INFO"
		Show-Goodbye
		
		# Auto-close terminal dengan countdown
		Show-CountdownAndClose -Seconds 5
	}
}

# ==================== SCRIPT ENTRY POINT ====================

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 4) {
    Write-Host "❌ PowerShell 4.0 atau lebih baru diperlukan!" -ForegroundColor Red
    Write-Host "💡 Versi Anda: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host "🔧 Script ini compatible dengan PowerShell 4.0+ untuk Windows 7/8/8.1/10/11" -ForegroundColor Yellow
    exit 1
}

# Run main function
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Main
    } catch {
        Write-Host "`n❌ Error: $($_.Exception.Message)" -ForegroundColor Red
        try {
            Write-LogEntry "Fatal error: $($_.Exception.Message)" "ERROR"
        } catch {}
        exit 1
    } finally {
        # Ensure clean exit
        try {
            if (Get-Variable -Name "Global:LogFile" -ErrorAction SilentlyContinue) {
                Write-LogEntry "Script execution completed" "INFO"
            }
        } catch {}
        exit 0
    }
}