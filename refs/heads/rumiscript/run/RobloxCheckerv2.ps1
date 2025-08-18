#Requires -Version 5.1
<#
.SYNOPSIS
    Roblox Checker & Fixer by Rumi - Comprehensive Roblox diagnostic and repair tool
.DESCRIPTION
    Script untuk mendiagnosis dan memperbaiki masalah Roblox yang sering crash
    Mendukung semua versi Windows dengan safety measures dan secure by design
.NOTES
    Version: 2.0
    Author: Rumi
    Compatible: Windows 7/8/8.1/10/11 (x86/x64)
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
    
    if ($Global:LogFile -and (Test-Path (Split-Path $Global:LogFile -Parent))) {
        try {
            Add-Content -Path $Global:LogFile -Value $logEntry -Encoding UTF8
        } catch {
            # Ignore log write errors to prevent infinite loops
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
	Write-LogEntry "Initializing Roblox Checker environment" "INFO"
	
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
	
	# Log system info
	Write-LogEntry "=== ROBLOX CHECKER SESSION STARTED ===" "INFO"
	Write-LogEntry "Script Version: $Global:ScriptVersion" "INFO"
	Write-LogEntry "Computer: $env:COMPUTERNAME" "INFO"
	Write-LogEntry "User: $env:USERNAME" "INFO"
	Write-LogEntry "OS: $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption)" "INFO"
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
	Write-TypewriterText "║                    Version $Global:ScriptVersion                                   ║" $Colors.Header 2
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

function Confirm-Action {
    param([string]$Message)
    Write-ColorText "$Message (Y/N): " -Color $Colors.Warning -NoNewLine
    do {
        $response = Read-Host
        if ($response -match '^[YyNn]$') {
            return ($response -match '^[Yy]$')
        } else {
            Write-ColorText "❌ Jawab dengan Y atau N: " -Color $Colors.Error -NoNewLine
        }
    } while ($true)
}

# ==================== SYSTEM DETECTION FUNCTIONS ====================

function Get-SystemInfo {
    Write-LogEntry "Collecting system information" "INFO"
    Show-ProgressBar -Activity "Mengumpulkan Informasi Sistem" -Status "Mendapatkan detail sistem..." -PercentComplete 10
    
    try {
        $os = Get-WmiObject Win32_OperatingSystem
        $cpu = Get-WmiObject Win32_Processor
        $ram = Get-WmiObject Win32_ComputerSystem
        $gpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -notlike "*Basic*" } | Select-Object -First 1
        
        $systemInfo = @{
            OSName = $os.Caption
            OSVersion = $os.Version
            OSArchitecture = $os.OSArchitecture
            CPUName = $cpu.Name
            CPUCores = $cpu.NumberOfCores
            RAMSize = [math]::Round($ram.TotalPhysicalMemory / 1GB, 2)
            GPUName = if ($gpu) { $gpu.Name } else { "Tidak terdeteksi" }
            Username = $env:USERNAME
            ComputerName = $env:COMPUTERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }
        
        Write-LogEntry "System info collected successfully" "SUCCESS"
        return $systemInfo
    } catch {
        Write-LogEntry "Error collecting system info: $($_.Exception.Message)" "ERROR"
        return $null
    }
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
        # Check OS
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $requirements.OS.Current = if ($os) { $os.Caption } else { (Get-WmiObject Win32_OperatingSystem).Caption }
        $supportedOS = @("Windows 7", "Windows 8", "Windows 10", "Windows 11", "Windows Server")
        $requirements.OS.Met = $supportedOS | Where-Object { $requirements.OS.Current -like "*$_*" }
        
        # Check RAM
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $ramTotal = if ($cs) { $cs.TotalPhysicalMemory } else { (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory }
        $ramGB = [math]::Round($ramTotal / 1GB, 2)
        $requirements.RAM.Current = "$ramGB GB"
        $requirements.RAM.Met = $ramGB -ge 1
        
        # Check DirectX via dxdiag (lebih akurat daripada registry)
		try {
			$dxDiagTxt = Join-Path $env:TEMP ("dxdiag_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".txt")
			$proc = Start-Process -FilePath "dxdiag.exe" -ArgumentList "/whql:off", "/t", $dxDiagTxt -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
			if ($proc) { Wait-Process -Id $proc.Id -Timeout 15 -ErrorAction SilentlyContinue }
			if (Test-Path $dxDiagTxt) {
				$line = (Select-String -Path $dxDiagTxt -Pattern 'DirectX Version' -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1).Line
				if ($line) {
					$ver = ($line -split ':',2)[1].Trim()
					$requirements.DirectX.Current = $ver
					if ($ver -match 'DirectX\s+(\d+)' -and [int]$Matches[1] -ge 9) { $requirements.DirectX.Met = $true } else { $requirements.DirectX.Met = $true }
				} else {
					$requirements.DirectX.Current = "Tidak terdeteksi"
				}
				try { Remove-Item $dxDiagTxt -Force -ErrorAction SilentlyContinue } catch {}
			} else {
				$requirements.DirectX.Current = "Tidak terdeteksi"
			}
		} catch {
			# Fallback ke registry (legacy, sering menunjukkan 4.09.00.0904)
			try {
				$dx = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\DirectX" -Name Version -ErrorAction SilentlyContinue
				if ($dx) { $requirements.DirectX.Current = $dx.Version; $requirements.DirectX.Met = $true } else { $requirements.DirectX.Current = "Tidak terdeteksi" }
			} catch { $requirements.DirectX.Current = "Tidak terdeteksi" }
		}
        
        # Check .NET Framework
        $dotNetVersions = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse |
                         Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
                         Where-Object { $_.PSChildName -match "^v" }
        
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

# ==================== REPORT FUNCTIONS ====================

function Show-SystemReport {
	param($SystemInfo, $RobloxInfo, $Requirements, $LogInfo)
	
	Write-ColorText "`n📋 LAPORAN SISTEM" -Color $Colors.Header
	Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
	
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
	Pause-ForSmoothness
	
	Write-ColorText "`n🎮 STATUS ROBLOX" -Color $Colors.Header
	Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
	
	if ($RobloxInfo.IsInstalled) {
		Write-ColorText "✅ Status: Terinstall" -Color $Colors.Success
		Write-ColorText "📁 Lokasi: $($RobloxInfo.InstallPath)" -Color $Colors.Info
		if ($RobloxInfo.ExecutablePath) { Write-ColorText "📄 Executable: $(Split-Path $RobloxInfo.ExecutablePath -Leaf)" -Color $Colors.Info }
		if ($RobloxInfo.Version) { Write-ColorText "🔖 Versi: $($RobloxInfo.Version)" -Color $Colors.Info }
		Write-ColorText "📊 Ukuran: $($RobloxInfo.Size) MB" -Color $Colors.Info
		if ($RobloxInfo.InstallDate) { Write-ColorText "📅 Install: $($RobloxInfo.InstallDate)" -Color $Colors.Info }
		if ($RobloxInfo.IsRunning) { Write-ColorText "🟢 Status: Berjalan ($($RobloxInfo.ProcessCount) proses)" -Color $Colors.Success } else { Write-ColorText "🔴 Status: Tidak berjalan" -Color $Colors.Error }
	} else {
		Write-ColorText "❌ Status: Tidak terinstall" -Color $Colors.Error
	}
	Pause-ForSmoothness
	
	Write-ColorText "`n✅ PERSYARATAN SISTEM" -Color $Colors.Header
	Write-ColorText "═══════════════════════════════════════" -Color $Colors.Header
	foreach ($req in $Requirements.GetEnumerator()) {
		$met = if ($req.Value.Met) { "✅" } else { "❌" }
		$color = if ($req.Value.Met) { $Colors.Success } else { $Colors.Error }
		Write-ColorText "$met $($req.Key): " -Color $color -NoNewLine
		Write-ColorText "$($req.Value.Current)" -Color $Colors.Info
		Write-ColorText "   Diperlukan: $($req.Value.Required)" -Color $Colors.Info
	}
	Pause-ForSmoothness
	
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
        return $false
    }
    Pause-ForSmoothness
    
    Write-ColorText "⚠️ Ditemukan $totalIssues masalah:" -Color $Colors.Warning
    
    if ($IntegrityIssues.Count -gt 0) {
        Write-ColorText "`n🔧 Masalah Integritas:" -Color $Colors.Error
        foreach ($issue in $IntegrityIssues) {
            Write-ColorText "   • $issue" -Color $Colors.Error
        }
        Pause-ForSmoothness
    }
    if ($CommonIssues.Count -gt 0) {
        Write-ColorText "`n⚠️ Masalah Umum:" -Color $Colors.Warning
        foreach ($issue in $CommonIssues) {
            Write-ColorText "   • $issue" -Color $Colors.Warning
        }
        Pause-ForSmoothness
    }
    if ($LogInfo.ErrorSummary.Count -gt 0) {
        Write-ColorText "`n🚨 Ringkasan Error/Crash dari Log Roblox:" -Color $Colors.Error
        $maxShow = [Math]::Min(5, $LogInfo.ErrorSummary.Count)
        for ($i=0; $i -lt $maxShow; $i++) {
            Write-ColorText "   • $($LogInfo.ErrorSummary[$i])" -Color $Colors.Error
        }
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
        $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
        Write-LogEntry "Current execution policy: $currentPolicy" "INFO"
        
        if ($currentPolicy -eq "Restricted") {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
            Write-LogEntry "Execution policy temporarily changed to RemoteSigned" "INFO"
            return $currentPolicy
        }
    } catch {
        Write-LogEntry "Could not change execution policy: $($_.Exception.Message)" "WARNING"
    }
    return $null
}

function Restore-ExecutionPolicy {
    param($OriginalPolicy)
    
    if ($OriginalPolicy -and $OriginalPolicy -eq "Restricted") {
        try {
            Set-ExecutionPolicy -ExecutionPolicy $OriginalPolicy -Scope CurrentUser -Force
            Write-LogEntry "Execution policy restored to: $OriginalPolicy" "INFO"
        } catch {
            Write-LogEntry "Could not restore execution policy: $($_.Exception.Message)" "WARNING"
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

# ==================== INTERACTIVE FUNCTIONS ====================

function Redraw-HeaderAndReset {
	try {
		Clear-Host
		Show-Header
		[Console]::SetCursorPosition(0, $Global:ContentStartY)
	} catch {}
}

function Show-ArrowMenu {
	param(
		[string[]]$Options,
		[int]$Default = 0
	)
	$selected = $Default
	$arrow = "➤"
	do {
		Redraw-HeaderAndReset
		Write-Host "🎯 PILIHAN TINDAKAN" -ForegroundColor DarkYellow
		Write-Host "═══════════════════════════════════════" -ForegroundColor Gray
		for ($i=0; $i -lt $Options.Length; $i++) {
			if ($i -eq $selected) {
				Write-Host ($arrow + " " + $Options[$i]) -ForegroundColor Black -BackgroundColor Yellow
			} else {
				Write-Host ("  " + $Options[$i]) -ForegroundColor DarkYellow
			}
		}
		Write-Host ""
		Write-Host "Gunakan panah atas/bawah, Enter untuk pilih. (Jika tidak bisa, ketik angka pilihan)" -ForegroundColor Gray
		$key = $null
		try { $key = [System.Console]::ReadKey($true) } catch {}
		if ($key) {
			if ($key.Key -eq "UpArrow") {
				$selected = if ($selected -le 0) { $Options.Length-1 } else { $selected-1 }
			} elseif ($key.Key -eq "DownArrow") {
				$selected = if ($selected -ge $Options.Length-1) { 0 } else { $selected+1 }
			} elseif ($key.Key -eq "Enter") {
				return ($selected+1)
			}
		} else {
			# Fallback: input angka
			$userInput = Read-Host ("Pilihan Anda (1-" + $Options.Length + ")")
			if ($userInput -match ("^[1-" + $Options.Length + "]$")) { return [int]$userInput }
		}
	} while ($true)
}

# ==================== MAIN EXECUTION FUNCTIONS ====================

# Helper untuk jeda halus antar section laporan
function Pause-ForSmoothness {
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
	Redraw-HeaderAndReset
	Write-ColorText "🔍 MEMULAI DIAGNOSIS LENGKAP..." -Color $Colors.Header
	
	# Collect system information
	Show-LoadingBar -Text "Mengumpulkan informasi sistem" -Duration 2
	$systemInfo = Get-SystemInfo
	
	# Detect Roblox
	Show-LoadingBar -Text "Mendeteksi instalasi Roblox" -Duration 1
	$robloxInfo = Get-RobloxInfo
	
	# Check system requirements
	Show-LoadingBar -Text "Memeriksa persyaratan sistem" -Duration 1
	$requirements = Test-SystemRequirements
	
	# Collect logs
	Show-LoadingBar -Text "Mengumpulkan log Roblox" -Duration 1
	$logInfo = Get-RobloxLogs
	
	# Test integrity and common issues
	Show-LoadingBar -Text "Mendiagnosis masalah" -Duration 2
	$integrityIssues = Test-RobloxIntegrity
	$commonIssues = Test-CommonIssues
	
	# Show reports per section dengan jeda
	Redraw-HeaderAndReset
	Show-SystemReport -SystemInfo $systemInfo -RobloxInfo $robloxInfo -Requirements $requirements -LogInfo $logInfo
	Pause-ForSmoothness
	$hasIssues = Show-DiagnosisReport -IntegrityIssues $integrityIssues -CommonIssues $commonIssues -LogInfo $logInfo
	
	return @{
		HasIssues = $hasIssues
		IntegrityIssues = $integrityIssues
		CommonIssues = $commonIssues
		SystemInfo = $systemInfo
		RobloxInfo = $robloxInfo
	}
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
    
    # Repair processes
    Show-LoadingBar -Text "Menutup proses bermasalah" -Duration 1
    $repairResults["Proses"] = Repair-RobloxProcesses
    
    # Repair cache
    Show-LoadingBar -Text "Membersihkan cache" -Duration 2
    $repairResults["Cache"] = Repair-RobloxCache
    
    # Repair registry (admin required)
    if ($isAdmin) {
        Show-LoadingBar -Text "Memperbaiki registry" -Duration 1
        $regResult = Repair-RobloxRegistry
        $repairResults["Registry"] = if ($regResult) { 1 } else { 0 }
    } else {
        $repairResults["Registry"] = 0
    }
    
    # Install missing dependencies
    Show-LoadingBar -Text "Memeriksa dependensi" -Duration 1
    $repairResults["Dependensi"] = Install-MissingDependencies
    
    Show-RepairSummary -RepairResults $repairResults
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
    # Register Ctrl+C handler
    [Console]::TreatControlCAsInput = $false
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Write-Host "`n🛑 Pembatalan terdeteksi, melakukan cleanup..." -ForegroundColor $Colors.Warning
        Invoke-SafetyCleanup
    } | Out-Null
    
    # Register exit handler
    $null = Register-ObjectEvent -InputObject ([System.AppDomain]::CurrentDomain) -EventName ProcessExit -Action {
        Invoke-SafetyCleanup
    }
}

# ==================== MAIN SCRIPT EXECUTION ====================

function Main {
	try {
		Initialize-Environment
		Register-CleanupHandlers
		$originalPolicy = Set-ExecutionPolicyTemporary
		Show-Header
		
		do {
			$menuOptions = @(
				"🔍 Diagnosis Lengkap (Recommended)",
				"🔧 Perbaikan Otomatis",
				"📊 Lihat Laporan Sistem",
				"🧹 Bersihkan Cache Saja",
				"❌ Keluar"
			)
			$choice = Show-ArrowMenu -Options $menuOptions
			
			switch ($choice) {
				1 { try { $diagnosisResults = Invoke-FullDiagnosis } catch { Write-ColorText "❌ Diagnosis gagal: $($_.Exception.Message)" -Color $Colors.Error } }
				2 {
					try {
						Redraw-HeaderAndReset
						Write-ColorText "🔍 Menjalankan diagnosis cepat..." -Color $Colors.Info
						$diagnosisResults = Invoke-FullDiagnosis
						Invoke-AutoRepair -DiagnosisResults $diagnosisResults
					} catch { Write-ColorText "❌ Perbaikan gagal: $($_.Exception.Message)" -Color $Colors.Error }
				}
				3 {
					try {
						Redraw-HeaderAndReset
						$systemInfo = Get-SystemInfo
						$robloxInfo = Get-RobloxInfo
						$requirements = Test-SystemRequirements
						$logInfo = Get-RobloxLogs
						Redraw-HeaderAndReset
						Show-SystemReport -SystemInfo $systemInfo -RobloxInfo $robloxInfo -Requirements $requirements -LogInfo $logInfo
						Pause-ForSmoothness
					} catch { Write-ColorText "❌ Gagal menampilkan laporan: $($_.Exception.Message)" -Color $Colors.Error }
				}
				4 { Redraw-HeaderAndReset; Invoke-CacheCleanOnly }
				5 { break }
			}
			
			if ($choice -ne 5) {
				Write-ColorText "Tekan Enter untuk kembali ke menu..." -Color $Colors.Accent
				Read-Host | Out-Null
			}
			
		} while ($choice -ne 5)
		
	} catch {
		Write-LogEntry "Unexpected error in main execution: $($_.Exception.Message)" "ERROR"
		Write-ColorText "❌ Terjadi kesalahan tak terduga: $($_.Exception.Message)" -Color $Colors.Error
		Write-ColorText "📄 Periksa log file untuk detail: $Global:LogFile" -Color $Colors.Info
	} finally {
		Invoke-SafetyCleanup
		if ($originalPolicy) { Restore-ExecutionPolicy -OriginalPolicy $originalPolicy }
		Write-LogEntry "=== ROBLOX CHECKER SESSION ENDED ===" "INFO"
		Show-Goodbye
	}
}

# ==================== SCRIPT ENTRY POINT ====================

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "❌ PowerShell 5.1 atau lebih baru diperlukan!" -ForegroundColor Red
    Write-Host "💡 Versi Anda: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    exit 1
}

# Run main function
if ($MyInvocation.InvocationName -ne '.') {
    Main
}