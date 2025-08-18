# Roblox Checker by Rumi

RobloxChecker.ps1 adalah script PowerShell modern, aman, dan interaktif untuk mendiagnosis, memperbaiki, dan membersihkan masalah Roblox di Windows. Dirancang dengan UI berwarna, animasi, log detail, serta workflow diagnosis & repair yang risk-free.

---

## ✨ Fitur Utama
- **Diagnosis lengkap**: Deteksi instalasi, status, versi, dan proses Roblox.
- **Cek persyaratan sistem**: RAM, OS, DirectX, .NET, Visual C++ Redistributable.
- **Parsing log Roblox**: Deteksi error/crash/exception dari log Roblox.
- **Repair otomatis & granular**: Bersihkan cache, registry, proses, dan cek dependensi.
- **UI modern**: Efek ketik, loading bar, progress, dan full Bahasa Indonesia.
- **Auto-elevate**: Otomatis meminta hak admin jika diperlukan.
- **Log detail**: Semua proses dan error tercatat di folder log khusus.
- **Auto cleanup**: Bersihkan file/temp/log sementara saat selesai atau dibatalkan.
- **Aman & risk free**: Tidak menghapus data penting, selalu backup sebelum repair.

---

## 🚀 Cara Penggunaan (One-liner)

### 1. **Jalankan via PowerShell (disarankan PowerShell 5.1+)**

#### **Dari Github Public (contoh):**
```powershell
irm https://raw.githubusercontent.com/<username>/<repo>/main/RobloxChecker.ps1 | iex
```
Ganti `<username>` dan `<repo>` sesuai repo Github kamu.

#### **Dari file lokal:**
```powershell
powershell -ExecutionPolicy Bypass -File .\RobloxChecker.ps1
```

### 2. **Script akan otomatis meminta hak admin jika diperlukan.**

---

## 📖 User Guide

### **Menu Utama**
1. **Diagnosis Lengkap**: Cek semua aspek Roblox & sistem, tampilkan report & ringkasan error/crash.
2. **Perbaikan Otomatis**: Diagnosis lalu repair otomatis jika ada masalah.
3. **Lihat Laporan Sistem**: Tampilkan info sistem, status Roblox, dan log.
4. **Bersihkan Cache Saja**: Hanya membersihkan cache Roblox.
5. **Keluar**: Tutup program dengan aman.

### **Diagnosis**
- Script akan mendeteksi instalasi Roblox, status proses, versi, lokasi, dan log error/crash.
- Cek persyaratan sistem (RAM, OS, DirectX, .NET, MSVC).
- Semua hasil diagnosis dan error/crash log ditampilkan di report.

### **Repair**
- Hanya dilakukan jika ada masalah.
- Repair proses: tutup proses Roblox bermasalah.
- Repair cache: bersihkan cache/temp Roblox (dengan backup).
- Repair registry: perbaiki registry Roblox (admin).
- Cek & info dependensi: .NET, Visual C++ Redistributable.
- Semua repair aman, tidak menghapus data penting.

### **Log & Report**
- Semua proses, error, dan hasil diagnosis/repair dicatat di folder log khusus.
- Log Roblox juga dicopy ke folder log checker.
- Path log bisa dibuka langsung via File Explorer (Ctrl+Click di terminal).

### **Auto Cleanup**
- File/temp/log sementara dibersihkan otomatis saat program selesai, dibatalkan, atau Ctrl+C.

---

## ❓ FAQ & Troubleshooting

**Q: Script tidak jalan atau error hak akses?**
A: Jalankan PowerShell sebagai Administrator, atau pastikan Execution Policy mengizinkan script (script akan auto-bypass jika bisa).

**Q: Apakah data Roblox saya aman?**
A: Ya, script tidak menghapus data penting, hanya cache/temp/registry bermasalah, dan selalu backup sebelum repair.

**Q: Bagaimana jika Roblox tetap error setelah repair?**
A: Coba restart komputer, update Windows/driver, atau reinstall Roblox. Cek juga log di folder log checker untuk detail error.

**Q: Apakah script ini bisa menyebabkan banned?**
A: Tidak, script hanya diagnosis & repair standar, tidak menyentuh data game/user, dan tidak trigger anti-cheat.

---

## 🔒 Catatan Keamanan
- Script tidak menghapus data penting.
- Semua repair berbasis hasil diagnosis, tidak ada destructive action.
- Selalu backup registry/cache sebelum repair.
- Tidak ada koneksi keluar selain download dependensi (hanya info link, tidak auto-download).

---

## 🤝 Kontribusi & Lisensi
- Kontribusi, saran, dan bug report sangat diterima! Silakan buat issue atau pull request.
- Lisensi: MIT (bebas digunakan, mohon tetap cantumkan kredit).

---

**Roblox Checker by Rumi**

---

## 🔐 Penggunaan dari Repo Github Private

Jika repo kamu **private**, ada beberapa hal penting:

### 1. **Akses via Token (Personal Access Token/PAT)**
- Github tidak mengizinkan akses raw file dari repo private tanpa autentikasi.
- Untuk menggunakan `irm ... | iex` dari repo private, kamu harus:
  1. **Generate Personal Access Token (PAT)** di Github (minimal scope: `repo` atau `read:packages`).
  2. Gunakan token tersebut di header permintaan, contoh:
     ```powershell
     $headers = @{ Authorization = "token <YOUR_TOKEN>" }
     irm -Headers $headers https://raw.githubusercontent.com/<username>/<repo>/main/RobloxChecker.ps1 | iex
     ```
  3. **Jangan pernah share token ke orang lain!**

### 2. **Akses via SSH**
- `irm` (Invoke-RestMethod) **tidak mendukung** akses raw file via SSH URL.
- Untuk clone repo private via SSH:
  ```bash
  git clone git@github.com:<username>/<repo>.git
  cd <repo>
  powershell -ExecutionPolicy Bypass -File .\RobloxChecker.ps1
  ```
- **Tidak bisa** langsung one-liner `irm ... | iex` dari SSH.

### 3. **Saran**
- Untuk distribusi mudah via one-liner, gunakan repo **public** atau upload script ke Github Gist (public).
- Jika harus private, distribusi paling aman adalah download manual atau clone repo, lalu jalankan script secara lokal.

---

## ☁️ Cara Push Script Lokal ke Github

### 1. **Buat Repo Baru di Github**
- Buka https://github.com/new
- Isi nama repo, deskripsi, dan buat repo (public/private sesuai kebutuhan)

### 2. **Inisialisasi Git di Folder Script**
Buka terminal di folder script (misal: `RobloxChecker.ps1` & `README.md` sudah ada di situ):
```bash
git init
git add .
git commit -m "Initial commit: RobloxChecker by Rumi"
```

### 3. **Hubungkan ke Repo Github**
Ganti `<username>` dan `<repo>` sesuai milikmu:
```bash
git remote add origin https://github.com/<username>/<repo>.git
git branch -M main
git push -u origin main
```

### 4. **Jika Repo Sudah Ada (Sudah Pernah di-init)**
```bash
git add .
git commit -m "Update script dan README"
git push
```

### 5. **Cek di Github**
- Buka repo di browser, pastikan file sudah muncul.
- Setelah itu, kamu bisa pakai one-liner `irm ... | iex` sesuai instruksi di atas.

---
