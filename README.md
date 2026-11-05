# 🛡️ Waskita — Laravel Security Audit Engine (`waskita/security`)

> **Automated Laravel Security Testing & Vulnerability Audit Engine for AI Agents & CI/CD Pipelines**

> *Dari bahasa Jawa Kuno/Sanskerta **'Waskitha'** yang berarti **'tajam penglihatan batinnya, mampu melihat apa yang tersembunyi dan tidak tampak oleh mata biasa'**. Waskita dirancang untuk melihat titik buta keamanan yang dilewatkan oleh static analysis biasa: IDOR tersembunyi, bypass XSS, celah logika bisnis, dan konfigurasi tidak aman yang luput dari perhatian.*

[![Latest Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://packagist.org/packages/waskita/security)
[![PHP Version](https://img.shields.io/badge/php-%5E8.2-777bb4.svg)](https://php.net)
[![Laravel Support](https://img.shields.io/badge/laravel-11.x%20%7C%2012.x-ff2d20.svg)](https://laravel.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Daftar Isi

1. [Latar Belakang & Masalah Keamanan Laravel](#-latar-belakang--masalah-keamanan-laravel)
2. [Fitur Utama](#-fitur-utama)
3. [Metode Instalasi](#-metode-instalasi)
   - [Metode 1: Composer Package (Rekomendasi Proyek)](#metode-1-composer-package-dalam-proyek-laravel)
   - [Metode 2: Git Clone (Standalone Runner)](#metode-2-git-clone-standalone-runner)
4. [Panduan Penggunaan Perintah CLI](#-panduan-penggunaan-perintah-cli)
   - [`php artisan waskita:audit`](#1-php-artisan-waskitaaudit)
   - [`php artisan waskita:audit --format=agent`](#2-php-artisan-waskitaaudit---formatagent-untuk-ai-agent)
   - [`php artisan waskita:headers`](#3-php-artisan-waskitaheaders-url)
   - [`php artisan waskita:generate-rules`](#4-php-artisan-waskitagenerate-rules)
5. [Konsumsi Output oleh AI Agent (Hermes, Claude, Copilot)](#-konsumsi-output-oleh-ai-agent)
   - [Spesifikasi JSON Schema](#spesifikasi-json-schema-agent)
   - [Alur Kerja Remediasi Mandiri (Autonomous Remediation)](#alur-kerja-remediasi-mandiri)
6. [Integrasi CI/CD Pipeline (GitHub Actions)](#-integrasi-cicd-pipeline-github-actions)
7. [Struktur & Sintaks Aturan Kustom YAML](#-struktur--sintaks-aturan-kustom-yaml)
8. [Aturan Keamanan Bawaan (Default Rules)](#-aturan-keamanan-bawaan-default-rules)
9. [Kontribusi & Lisensi](#-kontribusi--lisensi)

---

## 💡 Latar Belakang & Masalah Keamanan Laravel

Laravel adalah framework PHP modern yang sangat populer, produktif, dan dilengkapi banyak fitur keamanan bawaan seperti Eloquent ORM (prepared statements), Blade escaping, dan CSRF protection.

Namun dalam praktiknya di dunia nyata, **banyak celah keamanan fatal tetap lolos ke tahap produksi**. Mengapa hal tersebut bisa terjadi? Waskita diciptakan untuk menjawab **6 Masalah Keamanan Utama** berikut:

### 1. Proteksi Default Laravel Berhenti di Level Formulir dan Sintaks, Bukan Hak Kepemilikan (Ownership) dan Logika Bisnis
* **SQL Injection**: Eloquent memang mengamankan parameter `where('col', $val)`. Namun saat developer membuat pengurutan dinamis `$query->orderBy($request->sort_by)` atau menggunakan `DB::raw()`, prepared statement tidak bekerja pada nama kolom atau string concatenation.
* **XSS pada Blade**: Directive `{!! $konten !!}` digunakan luas untuk rendering teks kaya (WYSIWYG editor). Tanpa sanitasi aktif seperti HTMLPurifier, script jahat tersimpan bebas dieksekusi di browser korban.
* **CSRF Exclusions Abuse**: Demi mempercepat integrasi API atau webhook pembayaran, developer sering kali menambahkan wildcard `'*'` atau rute sensitif (`login`, `password/reset`) ke dalam array `$except` pada middleware `VerifyCsrfToken`.
* **IDOR (Insecure Direct Object Reference)**: Laravel menyediakan Route Model Binding (`Route::get('/berita/{berita}/edit')`), tetapi Laravel **tidak secara otomatis memeriksa apakah user yang sedang login berhak menyunting record tersebut**. Jika developer lupa menulis Policy atau Gate, user mana pun dapat mengubah ID di URL untuk memanipulasi data user lain.
* **Mass Assignment via `$guarded = []`**: Banyak tutorial dan jalan pintas pengembang yang menggunakan `protected $guarded = [];` agar tidak repot mendaftarkan field di `$fillable`. Hal ini membuka pintu bagi penyerang untuk mengirimkan payload tersembunyi seperti `role=admin` atau `is_admin=1` saat registrasi atau pembaruan profil.

### 2. Keterbatasan Alat Analisis Statis yang Ada (Static Analysis Limitations)
* Tool seperti **PHPStan** atau **Larastan** sangat hebat dalam menemukan *type mismatch* atau pemanggilan method yang tidak ada, tetapi mereka **buta terhadap konteks logika bisnis dan bypass XSS/IDOR**.
* Perintah `composer audit` hanya memeriksa database advisori CVE untuk dependensi pihak ketiga di `composer.lock`, sama sekali **tidak memeriksa baris kode aplikasi Anda sendiri**.

### 3. Penetration Testing Dinamis Memerlukan Tool Eksternal yang Rumit dan Mahal
* Tool Dynamic Application Security Testing (DAST) tradisional seperti OWASP ZAP, Burp Suite, atau Nessus memerlukan konfigurasi rumit, waktu pemindaian berjam-jam, serta biaya lisensi ribuan dolar yang sulit dijangkau tim kecil maupun mahasiswa magang.

### 4. Kerentanan Paling Sering Lolos dan Paling Berbahaya di Ekosistem Laravel
* **`APP_DEBUG=true` di Lingkungan Production (CVE-2021-3129)**: Mengizinkan penyerang mengeksekusi kode dari jarak jauh (Remote Code Execution / RCE) melalui komponen Laravel Ignition facade deserialization.
* **`APP_KEY` Kosong atau Nilai Default (CVE-2018-15133)**: Memungkinkan penyerang membuat payload serialized session cookie yang ditandatangani dengan kunci default untuk memicu deserialization RCE.
* **IDOR Horizontal & Vertikal**: Terjadi di lebih dari 40% aplikasi internal Laravel yang tidak menerapkan `authorizeResource()` pada Resource Controllers.
* **Transitive Dependency CVEs**: Paket lama yang tidak diperbarui di lingkungan server on-premise.

### 5. Tidak Adanya Monitoring Keamanan Berkelanjutan (Continuous Security Monitoring)
* Sebagian besar tim hanya melakukan audit keamanan satu kali saat rilis awal (*one-off pentest*). Setiap ada commit atau fitur baru, risiko regresi celah keamanan kembali terbuka tanpa adanya pengawasan otomatis di CI/CD.

### 6. Kebutuhan Menghubungkan Audit Keamanan dengan Ekosistem AI Coding Agent
* Generasi developer saat ini telah banyak berkolaborasi dengan AI Agent (seperti Hermes Agent, Claude Code, Cursor, Copilot). Namun alat audit yang ada menghasilkan log teks panjang yang sulit diparse atau tidak menyertakan saran perbaikan terstruktur. Waskita menyajikan format data **Agent-Ready JSON** yang dirancang khusus untuk memandu LLM membaca temuan, memahami konteks, dan langsung melakukan perbaikan kode secara mandiri.

---

## 🚀 Fitur Utama

- 🔍 **Multi-Vector Security Scanners**:
  - **Model Scanner**: Mendeteksi `$guarded = []`, kolom sensitif di `$fillable`, dan ketiadaan perlindungan Mass Assignment.
  - **Controller & IDOR Scanner**: Mendeteksi Route Model Binding tanpa Policy/Gate, `findOrFail` tanpa ownership scope, dan controller tanpa `authorizeResource()`.
  - **Blade Template Scanner**: Memeriksa penggunaan berbahaya `{!! !!}`, input request langsung tanpa escape, dan script attribute injection.
  - **SQLi Scanner**: Mendeteksi interpolasi/konkatenasi pada `DB::raw()`, `whereRaw()`, serta `orderBy` dinamis tanpa whitelist.
  - **CSRF Scanner**: Memvalidasi integritas `VerifyCsrfToken` `$except` dan formulir Blade tanpa `@csrf`.
  - **Environment Scanner**: Audit instan nilai `.env` (`APP_DEBUG`, `APP_KEY`, `SESSION_SECURE_COOKIE`).
  - **Headers Scanner**: Audit langsung HTTP Security Headers (HSTS, CSP, X-Frame-Options, dll.) pada domain target aktif.
  - **Rate Limiting Scanner**: Memeriksa perlindungan brute force pada rute otentikasi.
- 🤖 **AI-Agent Ready Engine**: Ekspor laporan dalam format JSON standar (`--format=agent`) yang memuat *code snippet*, baris lokasi presisi, dan panduan perbaikan langkah-demi-langkah bagi model LLM.
- 📋 **Flexible Custom YAML Rules**: Tulis aturan keamanan unik aplikasi Anda dengan sintaks YAML deklaratif yang mudah dipahami.
- ⚡ **Zero-Dependency Core**: Menggunakan modul bawaan Laravel dan Symfony YAML tanpa memerlukan server pendukung tambahan.
- 🚦 **CI/CD Integration**: Exit code otomatis (`--fail-on=high`) dan stub GitHub Actions siap pakai untuk memblokir pull request yang mengandung celah kritis.

---

## 📦 Metode Instalasi

Anda dapat menggunakan Waskita dengan dua cara sesuai skenario penggunaan Anda:

### Metode 1: Composer Package (Dalam Proyek Laravel)

Pilihan terbaik jika Anda ingin menjalankan audit langsung di dalam repositori Laravel yang sedang dikembangkan:

```bash
# 1. Pasang paket ke dalam proyek Laravel Anda
composer require --dev waskita/security

# 2. Publish file konfigurasi dan template aturan kustom
php artisan vendor:publish --tag=waskita-config
php artisan vendor:publish --tag=waskita-rules

# 3. Jalankan audit pertama Anda
php artisan waskita:audit
```

> **Catatan:** ServiceProvider akan otomatis terdaftar melalui fitur *package auto-discovery* Laravel.

### Metode 2: Git Clone (Standalone Runner)

Pilihan tepat jika Anda adalah tim QA, security auditor, atau konsultan yang ingin mengaudit repositori klien tanpa memodifikasi file `composer.json` proyek target:

```bash
# 1. Clone repositori Waskita
git clone https://github.com/waskita/security.git waskita
cd waskita

# 2. Pasang dependensi
composer install

# 3. Jalankan audit terhadap direktori proyek target
php artisan waskita:audit --path=/path/ke/proyek-laravel-target
```

---

## 💻 Panduan Penggunaan Perintah CLI

Waskita menyediakan perintah Artisan yang fleksibel dan informatif:

### 1. `php artisan waskita:audit`

Menjalankan pemindaian menyeluruh terhadap seluruh kode sumber aplikasi:

```bash
# Audit standar dengan output tabel interaktif di terminal
php artisan waskita:audit

# Memindai hanya kategori tertentu
php artisan waskita:audit --category=idor,mass-assignment,xss

# Memindai direktori proyek spesifik
php artisan waskita:audit --path=/var/www/my-laravel-app

# Menentukan ambang batas kegagalan untuk CI/CD (critical, high, medium, low)
php artisan waskita:audit --fail-on=high
```

### 2. `php artisan waskita:audit --format=agent` (Untuk AI Agent)

Menghasilkan keluaran JSON terstruktur yang ditujukan untuk dibaca oleh AI coding agent (Hermes, Claude, GPT, Cursor):

```bash
# Menampilkan output JSON ke stdout
php artisan waskita:audit --format=agent

# Menyimpan hasil audit langsung ke file JSON
php artisan waskita:audit --format=agent --output=waskita-report.json
```

### 3. `php artisan waskita:headers {url}`

Memeriksa secara langsung kelengkapan HTTP Security Headers pada aplikasi web yang sedang aktif (staging atau production):

```bash
# Audit header pada server lokal
php artisan waskita:headers http://localhost:8000

# Audit header pada domain produksi
php artisan waskita:headers https://koni.kotadepok.go.id

# Simpan hasil dalam format JSON
php artisan waskita:headers https://my-app.com --format=json
```

Header yang diperiksa mencakup:
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

### 4. `php artisan waskita:generate-rules`

Membuat berkas template aturan kustom YAML baru untuk logika aplikasi Anda:

```bash
# Membuat template aturan kustom di folder rules/custom/
php artisan waskita:generate-rules --name=transaksi-rules
```

---

## 🤖 Konsumsi Output oleh AI Agent

Waskita dirancang khusus agar dapat menjadi "mata" keamanan bagi AI Autonomous Coding Agents — sesuai filosofi namanya yang berarti *'tajam penglihatan batinnya'*. Format JSON keluaran `--format=agent` menyediakan seluruh data yang diperlukan model AI untuk melakukan *Root Cause Analysis* dan menuliskan *Patch* secara otomatis.

### Spesifikasi JSON Schema (`--format=agent`)

```json
{
  "scan_id": "waskita_20261105_091530",
  "engine_version": "1.0.0",
  "target_path": "/var/www/web-koni",
  "timestamp": "2026-11-05T09:15:30Z",
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  },
  "findings": [
    {
      "rule_id": "MA-001",
      "category": "mass-assignment",
      "severity": "critical",
      "confidence": "high",
      "title": "Empty Guarded Array",
      "description": "Model User mendefinisikan $guarded = [], memungkinkan penyerang menyisipkan kolom admin.",
      "file": "app/Models/User.php",
      "line": 18,
      "snippet": "    protected $guarded = [];",
      "remediation": {
        "summary": "Ganti $guarded = [] dengan $fillable eksplisit.",
        "steps": [
          "Hapus properti $guarded = []",
          "Tambahkan $fillable = ['name', 'email', 'avatar']",
          "Pastikan field 'role' dan 'is_admin' tidak didaftarkan di $fillable"
        ]
      }
    },
    {
      "rule_id": "IDOR-001",
      "category": "idor",
      "severity": "high",
      "confidence": "high",
      "title": "Route Model Binding Without Authorization",
      "description": "Method BeritaController::edit() menerima Berita $berita tanpa Policy check.",
      "file": "app/Http/Controllers/BeritaController.php",
      "line": 42,
      "snippet": "    public function edit(Berita $berita)\n    {\n        return view('berita.edit', compact('berita'));\n    }",
      "remediation": {
        "summary": "Tambahkan $this->authorize('update', $berita); pada awal method.",
        "steps": [
          "Jalankan: php artisan make:policy BeritaPolicy --model=Berita",
          "Definisikan logic hak akses pada method update() di BeritaPolicy",
          "Sisipkan $this->authorize('update', $berita); di BeritaController::edit()"
        ]
      }
    }
  ]
}
```

### Alur Kerja Remediasi Mandiri

Jika Anda mengintegrasikan Waskita dengan Hermes Agent atau sistem coding agent lainnya:

```text
┌────────────────────────┐
│  Developer / CI Hook   │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ php artisan waskita:   │
│ audit --format=agent   │
└───────────┬────────────┘
            │ (Output JSON)
            ▼
┌────────────────────────┐
│   AI Coding Agent      │ 1. Parse JSON findings
│ (Hermes / Claude / ...)│ 2. Urutkan berdasarkan severity: critical -> high
└───────────┬────────────┘ 3. Baca kode di file:line yang tertera
            │              4. Terapkan rekomendasi patch
            ▼
┌────────────────────────┐
│ Automatic Patch Applied│
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ Re-run Validation Scan │ -> Jika lulus: Commit & Create Pull Request
└────────────────────────┘
```

---

## 🚦 Integrasi CI/CD Pipeline (GitHub Actions)

Waskita dapat dipasang pada alur integrasi berkelanjutan (CI) untuk mencegah celah keamanan lolos ke branch utama. 

Salin stub workflow yang tersedia:
```bash
mkdir -p .github/workflows
cp vendor/waskita/security/stubs/github-workflow.yml.stub .github/workflows/waskita-audit.yml
```

Atau gunakan konfigurasi `.github/workflows/waskita-audit.yml` berikut:

```yaml
name: Waskita Security Audit

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup PHP Environment
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
          extensions: mbstring, xml, ctype, iconv

      - name: Install Dependencies
        run: composer install --prefer-dist --no-progress

      - name: Jalankan Audit Waskita
        run: |
          php artisan waskita:audit --fail-on=high --format=github
```

Jika terdapat temuan dengan tingkat keparahan `high` atau `critical`, pipeline GitHub Actions akan otomatis menghasilkan status *failed* dan memberikan anotasi langsung pada baris pull request yang bermasalah.

---

## 📝 Struktur & Sintaks Aturan Kustom YAML

Waskita menggunakan format YAML sederhana dan mudah diperluas. Berkas aturan kustom ditempatkan di direktori `rules/custom/` pada proyek Anda:

```yaml
meta:
  id: my-project-rules
  name: "Aturan Bisnis Khusus Proyek"
  version: "1.0.0"
  category: custom
  description: "Memvalidasi hak akses khusus dan alur data internal"

rules:
  - id: PROJ-001
    name: "Cek Hak Akses Admin pada Controller Transaksi"
    severity: high
    confidence: high
    scanner: controller
    description: "Method update() pada TransaksiController harus memvalidasi permission transaksi.edit."
    pattern:
      type: php_method
      class: "TransaksiController"
      method: "update"
      missing_calls:
        - "authorize"
        - "Gate::"
    examples:
      vulnerable: |
        public function update(Request $request, Transaksi $transaksi) {
            $transaksi->update($request->validated());
        }
      secure: |
        public function update(Request $request, Transaksi $transaksi) {
            $this->authorize('update', $transaksi);
            $transaksi->update($request->validated());
        }
    remediation: "Gunakan $this->authorize('update', $transaksi) sebelum melakukan perubahan data."
```

---

## 🎯 Menyesuaikan dengan Konteks Bisnis Aplikasi

Tidak semua aplikasi Laravel memiliki arsitektur yang seragam. Waskita dirancang agar dapat menyesuaikan dengan aturan bisnis Anda, bukan memaksa aturan kaku:

### 1. Konfigurasi Role Context & IDOR (`config/waskita.php`)
Secara default, Waskita memahami bahwa **Admin Controller** (seperti `AdminBeritaController`) beroperasi dengan hak superuser dan tidak memerlukan pemeriksaan kepemilikan personal. Anda dapat mengatur pemetaan controller admin dan aksi publik di `config/waskita.php`:

```php
'idor' => [
    // Controller dengan hak superuser/admin (bebas dari warning IDOR kepemilikan)
    'admin_controllers' => [
        '*Admin*',
        '*AdminController',
        'App\Http\Controllers\Admin\*',
    ],

    // Aksi resource yang memang terbuka untuk dibaca publik
    'public_actions' => [
        'show',
        'download',
        'preview',
        'index',
    ],
],
```

### 2. Pengecualian Kode Sah (`@waskita-ignore`)
Jika ada baris kode yang sengaja ditulis untuk kebutuhan bisnis khusus dan telah diverifikasi aman, developer dapat menambahkan komentar `@waskita-ignore` tepat di baris kode atau baris sebelumnya tanpa harus mematikan rule secara global:

```php
// @waskita-ignore SQLI: Hierarki pengurus dibangun dari konstanta internal
return $query->orderByRaw($pernyataan.' else 99 end', $bindings);
```

Atau di template Blade:
```blade
{{-- @waskita-ignore XSS --}}
<div onclick="pilihFilterDropdown('kategori', '{{ $item }}')">
```

---

## 📚 Aturan Keamanan Bawaan (Default Rules)

Waskita dilengkapi dengan sekumpulan aturan bawaan (*built-in*) yang mencakup spektrum kerentanan paling krusial:

| File Aturan | Kategori | Ringkasan Pengecekan |
|---|---|---|
| `rules/default/mass-assignment-rules.yaml` | Mass Assignment | Deteksi `$guarded = []`, kolom sensitif di `$fillable`, penggunaan `$request->all()` pada method create/update. |
| `rules/default/idor-rules.yaml` | IDOR & Authn/z | Model binding tanpa Policy/Gate, `findOrFail` tanpa scope user ownership, Resource Controller tanpa `authorizeResource()`. |
| `rules/default/xss-rules.yaml` | Cross-Site Scripting | Penggunaan `{!! !!}` tanpa HTMLPurifier, pemanggilan variabel `$request` di dalam unescaped Blade, atribut event handler dinamis. |
| `rules/default/sqli-rules.yaml` | SQL Injection | Interpolasi variabel dalam `DB::raw()`, input request di method `whereRaw`/`orderByRaw`, dan dynamic `orderBy` tanpa whitelist. |
| `rules/default/csrf-rules.yaml` | CSRF Protection | Wildcard `'*'` atau rute sensitif dalam array `$except` `VerifyCsrfToken`, form Blade POST tanpa `@csrf`. |
| `rules/default/env-rules.yaml` | Environment & Secrets | `APP_DEBUG=true` di production (CVE-2021-3129), `APP_KEY` kosong/default (CVE-2018-15133), ketiadaan `SESSION_SECURE_COOKIE`. |
| `rules/default/headers-rules.yaml` | HTTP Security Headers | Kelengkapan HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| `rules/default/ratelimit-rules.yaml` | Rate Limiting | Ketiadaan middleware `throttle` pada endpoint POST login, register, dan permintaan reset kata sandi. |

---

## 🤝 Panduan Lengkap & Contoh Nyata

Untuk panduan perbaikan langkah-demi-langkah dengan cuplikan kode dari kasus nyata (misal: proyek **Web KONI**), silakan pelajari:

📖 **[PANDUAN.md](PANDUAN.md)** — Panduan praktis mitigasi celah keamanan Laravel.  
🤖 **[AGENT_PROMPT.md](AGENT_PROMPT.md)** — Prompt instruksi siap pakai untuk AI Coding Agent (Hermes / Claude).

---

## 📄 Lisensi & Kontribusi

Paket ini dirilis di bawah lisensi terbuka [MIT License](LICENSE).  
Kontribusi berupa pull request, penambahan aturan keamanan baru, atau perbaikan bug sangat disambut baik!
