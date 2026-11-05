# 📖 PANDUAN.md — Panduan Lengkap Penggunaan Waskita

> Panduan langkah-demi-langkah untuk **menginstal, menjalankan, membaca hasil audit, memperbaiki celah keamanan, dan mengotomasi** pemindaian keamanan Laravel menggunakan Waskita.

> *Dari bahasa Jawa Kuno/Sanskerta **'Waskitha'** yang berarti **'tajam penglihatan batinnya, mampu melihat apa yang tersembunyi dan tidak tampak oleh mata biasa'**. Waskita dirancang untuk melihat titik buta keamanan yang dilewatkan oleh static analysis biasa: IDOR tersembunyi, bypass XSS, celah logika bisnis, dan konfigurasi tidak aman yang luput dari perhatian.*

---

## Daftar Isi

- [Tahap 1: Instalasi & Persiapan](#tahap-1-instalasi--persiapan)
- [Tahap 2: Menjalankan Audit Keamanan Pertama Kali](#tahap-2-menjalankan-audit-keamanan-pertama-kali)
- [Tahap 3: Membaca Laporan & Contoh Perbaikan Celah Nyata](#tahap-3-membaca-laporan--contoh-perbaikan-celah-nyata)
  - [Kasus 1: Mengatasi IDOR dengan Laravel Policy](#kasus-1-mengatasi-idor-dengan-laravel-policy)
  - [Kasus 2: Menutup Celah Mass Assignment](#kasus-2-menutup-celah-mass-assignment-guarded-vs-fillable-vs-formrequest)
  - [Kasus 3: Sanitasi XSS pada {!! !!} dengan HTMLPurifier](#kasus-3-sanitasi-xss-pada---dengan-htmlpurifier)
  - [Kasus 4: Mencegah SQLi pada dynamic orderBy](#kasus-4-mencegah-sql-injection-pada-dynamic-orderby)
  - [Kasus 5: Mengamankan CSRF Exclusions](#kasus-5-mengamankan-csrf-exclusions)
  - [Kasus 6: Konfigurasi Security Headers (HSTS, CSP, X-Frame-Options)](#kasus-6-konfigurasi-security-headers)
- [Tahap 4: Menggunakan AI Agent untuk Audit dan Remediasi Otomatis](#tahap-4-menggunakan-ai-agent-untuk-audit-dan-remediasi-otomatis)
- [Tahap 5: Otomasi di CI/CD Pipeline (GitHub Actions)](#tahap-5-otomasi-di-cicd-pipeline-github-actions)
- [Tahap 6: Menulis Aturan Khusus (Custom YAML Rules)](#tahap-6-menulis-aturan-khusus-custom-yaml-rules)
- [Troubleshooting & FAQ](#troubleshooting--faq)

---

## Tahap 1: Instalasi & Persiapan

### Opsi A: Via Composer (Rekomendasi untuk Proyek Laravel)

Masuk ke direktori root proyek Laravel Anda, kemudian jalankan:

```bash
# 1. Tambahkan Waskita sebagai dev dependency
composer require --dev waskita/security

# 2. Publish konfigurasi dan template aturan kustom
php artisan vendor:publish --tag=waskita-config
php artisan vendor:publish --tag=waskita-rules

# 3. Verifikasi instalasi berhasil
php artisan list | grep waskita
```

Anda seharusnya melihat perintah berikut terdaftar:
```
waskita:audit           Jalankan pemindaian keamanan terhadap proyek Laravel
waskita:headers         Periksa HTTP security headers pada URL target
waskita:generate-rules  Buat template aturan keamanan kustom baru
```

### Opsi B: Via Git Clone (Standalone / Tim QA / Konsultan)

Jika Anda tidak ingin memodifikasi `composer.json` proyek target:

```bash
# 1. Clone repositori
git clone https://github.com/waskita/security.git waskita
cd waskita

# 2. Pasang dependensi
composer install

# 3. Jalankan audit terhadap proyek target di path berbeda
php artisan waskita:audit --path=/lokasi/proyek-laravel-target
```

---

## Tahap 2: Menjalankan Audit Keamanan Pertama Kali

Setelah instalasi berhasil, jalankan audit pertama Anda:

```bash
# Pemindaian lengkap semua kategori
php artisan waskita:audit
```

### Contoh Output Terminal

```
🛡️  Waskita Security Audit — v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Memindai: /var/www/web-koni
⏱  Waktu pemindaian: 2.4 detik

┌─────────┬──────────────────┬────────────┬───────────────────────────────────┬─────────────────────────────────────────┐
│ ID      │ Kategori         │ Keparahan  │ Lokasi                            │ Keterangan                              │
├─────────┼──────────────────┼────────────┼───────────────────────────────────┼─────────────────────────────────────────┤
│ MA-001  │ mass-assignment  │ 🔴 KRITIS  │ app/Models/User.php:18            │ Model $guarded = [] (terbuka penuh)     │
│ IDOR-001│ idor             │ 🔴 KRITIS  │ app/Http/.../BeritaCtrl.php:42    │ Route Model Binding tanpa authorize()   │
│ XSS-001 │ xss              │ 🟠 TINGGI  │ resources/views/berita/show:14    │ {!! $berita->konten !!} tanpa Purifier  │
│ SQLI-003│ sqli             │ 🟠 TINGGI  │ app/Http/.../ProdukCtrl.php:67    │ orderBy($request->sort) tanpa whitelist │
│ ENV-001 │ env              │ 🔴 KRITIS  │ .env:3                            │ APP_DEBUG=true pada production          │
│ HDR-003 │ headers          │ 🟠 TINGGI  │ (HTTP response)                   │ X-Frame-Options header tidak ditemukan  │
│ RATE-001│ ratelimit        │ 🟠 TINGGI  │ routes/web.php:28                 │ POST /login tanpa throttle middleware   │
└─────────┴──────────────────┴────────────┴───────────────────────────────────┴─────────────────────────────────────────┘

📊 Ringkasan: 3 Kritis, 4 Tinggi, 0 Sedang, 0 Rendah (Total: 7 temuan)
❌ Audit GAGAL — ditemukan 3 celah kritis yang harus segera diperbaiki.
```

### Format Output Lainnya

```bash
# Format JSON terstruktur untuk AI Agent
php artisan waskita:audit --format=agent

# Simpan ke file
php artisan waskita:audit --format=agent --output=storage/waskita/report.json

# Hanya pindai kategori tertentu
php artisan waskita:audit --category=idor,mass-assignment

# Gagalkan pipeline jika ada temuan >= high
php artisan waskita:audit --fail-on=high
```

---

## Tahap 3: Membaca Laporan & Contoh Perbaikan Celah Nyata

Berikut adalah panduan perbaikan langkah-demi-langkah untuk setiap jenis celah yang paling sering ditemukan:

---

### Kasus 1: Mengatasi IDOR dengan Laravel Policy

**Temuan:** `IDOR-001` — Controller `BeritaController::edit()` menerima `Berita $berita` via Route Model Binding tanpa pengecekan otorisasi.

**Bahaya:** User A bisa mengubah ID di URL menjadi `/berita/999/edit` untuk menyunting berita milik User B.

#### Langkah Perbaikan:

```bash
# 1. Buat Policy untuk model Berita
php artisan make:policy BeritaPolicy --model=Berita
```

```php
// app/Policies/BeritaPolicy.php
namespace App\Policies;

use App\Models\Berita;
use App\Models\User;

class BeritaPolicy
{
    /**
     * Apakah user boleh melihat berita ini?
     */
    public function view(User $user, Berita $berita): bool
    {
        // Semua user yang login boleh melihat berita yang sudah terbit
        return $berita->status === 'terbit' || $berita->user_id === $user->id;
    }

    /**
     * Apakah user boleh mengedit berita ini?
     */
    public function update(User $user, Berita $berita): bool
    {
        // Hanya pemilik berita ATAU admin yang boleh mengedit
        return $user->id === $berita->user_id || $user->role === 'admin';
    }

    /**
     * Apakah user boleh menghapus berita ini?
     */
    public function delete(User $user, Berita $berita): bool
    {
        return $user->id === $berita->user_id || $user->role === 'admin';
    }
}
```

```php
// app/Http/Controllers/BeritaController.php
class BeritaController extends Controller
{
    public function __construct()
    {
        // ✅ Mendaftarkan otorisasi untuk semua method CRUD sekaligus
        $this->authorizeResource(Berita::class, 'berita');
    }

    public function edit(Berita $berita)
    {
        // Tidak perlu panggil $this->authorize() lagi karena sudah di-handle oleh constructor
        return view('berita.edit', compact('berita'));
    }

    public function update(Request $request, Berita $berita)
    {
        $berita->update($request->validated());
        return redirect()->back()->with('success', 'Berita berhasil diperbarui.');
    }
}
```

#### Verifikasi:
```bash
php artisan waskita:audit --category=idor
# ✅ Seharusnya IDOR-001 tidak muncul lagi untuk BeritaController
```

---

### Kasus 2: Menutup Celah Mass Assignment ($guarded vs $fillable vs FormRequest)

**Temuan:** `MA-001` — Model `User` menggunakan `$guarded = []` dan `MA-003` — Controller menggunakan `$request->all()`.

**Bahaya:** Penyerang dapat menyisipkan field tersembunyi `role=admin` atau `is_admin=1` saat mendaftar.

#### Langkah Perbaikan:

**Langkah 2a: Perbaiki Model**
```php
// ❌ SEBELUM (BERBAHAYA):
class User extends Authenticatable
{
    protected $guarded = []; // Semua kolom terbuka!
}

// ✅ SESUDAH (AMAN):
class User extends Authenticatable
{
    // Hanya kolom ini yang boleh diisi melalui mass assignment
    protected $fillable = [
        'name',
        'email',
    ];

    // Hidden dari serialisasi JSON (API response)
    protected $hidden = [
        'password',
        'remember_token',
    ];
}
```

**Langkah 2b: Buat FormRequest untuk validasi**
```bash
php artisan make:request StoreUserRequest
```

```php
// app/Http/Requests/StoreUserRequest.php
class StoreUserRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true; // Siapa saja boleh mendaftar
    }

    public function rules(): array
    {
        return [
            'name'     => ['required', 'string', 'max:255'],
            'email'    => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'confirmed', 'min:8'],
        ];
    }
}
```

**Langkah 2c: Perbaiki Controller**
```php
// ❌ SEBELUM:
public function store(Request $request) {
    User::create($request->all()); // Semua input masuk!
}

// ✅ SESUDAH:
public function store(StoreUserRequest $request) {
    $user = User::create($request->validated()); // Hanya field yang sudah divalidasi
    $user->password = bcrypt($request->password); // Password diatur eksplisit
    $user->save();
}
```

---

### Kasus 3: Sanitasi XSS pada {!! !!} dengan HTMLPurifier

**Temuan:** `XSS-001` — File `resources/views/berita/show.blade.php` baris 14 menggunakan `{!! $berita->konten !!}` tanpa sanitasi.

**Bahaya:** Jika penulis menyisipkan `<script>alert(document.cookie)</script>` ke konten WYSIWYG, semua pengunjung halaman tersebut terkena Stored XSS.

#### Langkah Perbaikan:

```bash
# 1. Instal HTMLPurifier
composer require mews/purifier

# 2. Publish konfigurasi (opsional)
php artisan vendor:publish --provider="Mews\Purifier\PurifierServiceProvider"
```

```php
// ❌ SEBELUM (BERBAHAYA):
<div class="article-body">
    {!! $berita->konten !!}
</div>

// ✅ SESUDAH (AMAN — sanitasi saat render):
<div class="article-body">
    {!! Purifier::clean($berita->konten) !!}
</div>
```

**Alternatif yang lebih baik — sanitasi saat menyimpan ke database:**
```php
// app/Http/Controllers/BeritaController.php
use Mews\Purifier\Facades\Purifier;

public function store(StoreBeritaRequest $request)
{
    $berita = new Berita();
    $berita->judul = $request->judul;
    $berita->konten = Purifier::clean($request->konten); // ✅ Sanitasi SEBELUM simpan
    $berita->user_id = auth()->id();
    $berita->save();
}
```

**Konfigurasi HTMLPurifier (`config/purifier.php`):**
```php
'settings' => [
    'default' => [
        'HTML.Allowed' => 'p,b,i,u,strong,em,a[href|title],ul,ol,li,br,img[src|alt|width|height],h2,h3,h4,blockquote,pre,code,table,thead,tbody,tr,th,td',
        'AutoFormat.RemoveEmpty' => true,
    ],
],
```

---

### Kasus 4: Mencegah SQL Injection pada Dynamic orderBy

**Temuan:** `SQLI-003` — Controller `ProdukController::index()` menggunakan `orderBy($request->sort_by)` tanpa whitelist.

**Bahaya:** Penyerang mengirim `?sort_by=(SELECT password FROM users LIMIT 1)` untuk mengekstrak data.

#### Langkah Perbaikan:

```php
// ❌ SEBELUM (BERBAHAYA):
public function index(Request $request)
{
    $produk = Produk::orderBy($request->input('sort_by'))->paginate();
    return view('produk.index', compact('produk'));
}

// ✅ SESUDAH (AMAN — whitelist kolom):
public function index(Request $request)
{
    $allowedSortColumns = ['nama', 'harga', 'stok', 'created_at'];
    $allowedDirections  = ['asc', 'desc'];

    $sortBy = in_array($request->input('sort_by'), $allowedSortColumns)
        ? $request->input('sort_by')
        : 'created_at'; // Default aman

    $direction = in_array($request->input('direction'), $allowedDirections)
        ? $request->input('direction')
        : 'desc'; // Default aman

    $produk = Produk::orderBy($sortBy, $direction)->paginate();
    return view('produk.index', compact('produk'));
}
```

**Atau validasi di FormRequest:**
```php
// app/Http/Requests/IndexProdukRequest.php
public function rules(): array
{
    return [
        'sort_by'   => ['sometimes', Rule::in(['nama', 'harga', 'stok', 'created_at'])],
        'direction' => ['sometimes', Rule::in(['asc', 'desc'])],
    ];
}
```

---

### Kasus 5: Mengamankan CSRF Exclusions

**Temuan:** `CSRF-001` — Middleware `VerifyCsrfToken` memiliki `$except = ['*']` (semua rute dikecualikan dari CSRF).

**Bahaya:** Penyerang bisa membuat halaman jebakan yang mengirimkan form POST ke aplikasi Anda atas nama korban.

#### Langkah Perbaikan:

```php
// ❌ SEBELUM (SANGAT BERBAHAYA):
class VerifyCsrfToken extends Middleware
{
    protected $except = [
        '*', // Seluruh aplikasi tanpa CSRF!
    ];
}

// ✅ SESUDAH (AMAN):
class VerifyCsrfToken extends Middleware
{
    protected $except = [
        // Hanya webhook pihak ketiga yang memang tidak mengirim CSRF token:
        'webhook/midtrans',        // Payment gateway callback
        'webhook/stripe',          // Stripe webhook
        'api/external/callback',   // Callback dari layanan eksternal
    ];
}
```

**Pastikan semua form Blade memiliki `@csrf`:**
```blade
{{-- ✅ Form yang benar --}}
<form action="{{ route('profil.update') }}" method="POST">
    @csrf
    @method('PUT')
    <input type="text" name="name" value="{{ old('name', $user->name) }}">
    <button type="submit">Simpan</button>
</form>
```

**Untuk AJAX request, sertakan header X-CSRF-TOKEN:**
```html
<meta name="csrf-token" content="{{ csrf_token() }}">
<script>
    fetch('/api/data', {
        method: 'POST',
        headers: {
            'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content'),
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ key: 'value' }),
    });
</script>
```

---

### Kasus 6: Konfigurasi Security Headers

**Temuan:** `HDR-001` s/d `HDR-004` — Header keamanan HSTS, CSP, X-Frame-Options, X-Content-Type-Options tidak ditemukan.

#### Langkah Perbaikan: Membuat SecurityHeadersMiddleware

```bash
php artisan make:middleware SecurityHeaders
```

```php
// app/Http/Middleware/SecurityHeaders.php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Cegah clickjacking
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        // Cegah MIME-type sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Kontrol referrer information
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Batasi akses fitur browser (kamera, mikrofon, lokasi)
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        // Content Security Policy (sesuaikan dengan kebutuhan proyek)
        $response->headers->set('Content-Security-Policy',
            "default-src 'self'; " .
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " .
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " .
            "font-src 'self' https://fonts.gstatic.com; " .
            "img-src 'self' data: https:; " .
            "object-src 'none'; " .
            "frame-ancestors 'self';"
        );

        // HSTS (hanya aktifkan jika sudah HTTPS penuh)
        if ($request->isSecure()) {
            $response->headers->set('Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );
        }

        return $response;
    }
}
```

**Daftarkan middleware:**

**Laravel 11+ (`bootstrap/app.php`):**
```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\App\Http\Middleware\SecurityHeaders::class);
})
```

**Laravel 10 (`app/Http/Kernel.php`):**
```php
protected $middleware = [
    // ...
    \App\Http\Middleware\SecurityHeaders::class,
];
```

**Verifikasi:**
```bash
php artisan waskita:headers http://localhost:8000
# ✅ Semua header seharusnya muncul sebagai 'AMAN'
```

---

## Tahap 4: Menggunakan AI Agent untuk Audit dan Remediasi Otomatis

Waskita dapat menjadi "penglihatan keamanan batin" bagi AI Coding Agent:

### Menggunakan Hermes Agent

```bash
# 1. Hasilkan laporan format agent
php artisan waskita:audit --format=agent --output=waskita-report.json

# 2. Berikan ke Hermes Agent dengan prompt instruksi
hermes "Baca file waskita-report.json. Untuk setiap temuan dengan severity 'critical' atau 'high', buka file yang tertera, pahami konteksnya, dan terapkan perbaikan sesuai panduan remediation yang ada di laporan. Setelah memperbaiki, jalankan ulang audit untuk memverifikasi."
```

### Prompt Siap Pakai untuk AI Agent

Lihat file [AGENT_PROMPT.md](AGENT_PROMPT.md) untuk prompt instruksi lengkap yang sudah dioptimalkan untuk Hermes Agent, Claude Code, atau GitHub Copilot.

### Alur Kerja Remediasi Otomatis

```
Developer jalankan:
  php artisan waskita:audit --format=agent --output=report.json

AI Agent menerima report.json:
  1. Parse dan urutkan findings berdasarkan severity (critical > high > medium)
  2. Untuk setiap finding:
     a. Buka file di lokasi (file:line)
     b. Pahami konteks kode (class, method, flow data)
     c. Terapkan remediation steps sesuai panduan
     d. Jalankan test yang ada (php artisan test)
  3. Re-run audit untuk verifikasi perbaikan
  4. Buat commit atau pull request

Output akhir:
  ✅ Semua celah critical/high telah diperbaiki dan diverifikasi.
```

---

## Tahap 5: Otomasi di CI/CD Pipeline (GitHub Actions)

### Setup Cepat

```bash
# 1. Salin stub workflow ke proyek Anda
mkdir -p .github/workflows
cp vendor/waskita/security/stubs/github-workflow.yml.stub .github/workflows/waskita-audit.yml

# 2. Commit dan push
git add .github/workflows/waskita-audit.yml
git commit -m "ci: tambah Waskita security audit pada pipeline"
git push
```

### Cara Kerja

1. Setiap kali ada **push ke branch `main`** atau **pull request dibuat**, GitHub Actions akan:
   - Checkout kode
   - Setup PHP 8.2
   - Instal dependensi Composer
   - Menjalankan `php artisan waskita:audit --fail-on=high`
2. Jika ditemukan celah **critical** atau **high**, pipeline akan **gagal** dan menampilkan ringkasan temuan di **GitHub Step Summary**.
3. Laporan audit JSON akan disimpan sebagai **artifact** yang bisa diunduh.

### Konfigurasi Sensitivitas

Anda dapat mengatur ambang batas kegagalan sesuai kebutuhan tim:

```yaml
# Hanya gagal jika ada temuan CRITICAL
- run: php artisan waskita:audit --fail-on=critical

# Gagal jika ada temuan HIGH ke atas (rekomendasi)
- run: php artisan waskita:audit --fail-on=high

# Gagal jika ada temuan MEDIUM ke atas (ketat)
- run: php artisan waskita:audit --fail-on=medium
```

---

## Tahap 6: Menulis Aturan Khusus (Custom YAML Rules)

Setiap proyek memiliki logika bisnis yang unik. Waskita memungkinkan Anda menulis aturan keamanan kustom dalam format YAML:

### Membuat Template Baru

```bash
php artisan waskita:generate-rules --name=bisnis-rules
# File baru dibuat di: rules/custom/bisnis-rules.yaml
```

### Contoh Aturan Bisnis Khusus

Misalnya, dalam proyek **E-Commerce**, Anda ingin memastikan bahwa harga produk tidak bisa diubah melalui mass assignment:

```yaml
meta:
  id: ecommerce-rules
  name: "E-Commerce Security Rules"
  version: "1.0.0"
  category: custom
  description: "Memproteksi harga, stok, dan status transaksi dari manipulasi."

rules:
  - id: ECOM-001
    name: "Harga Produk di Fillable"
    severity: critical
    confidence: high
    scanner: model
    description: >
      Model Produk memiliki kolom 'harga' di $fillable.
      Penyerang bisa memanipulasi harga saat menambah ke keranjang.
    pattern:
      type: php_property
      class_extends: "Illuminate\\Database\\Eloquent\\Model"
      property: "fillable"
      contains_any: ["harga", "price", "diskon", "discount"]
    remediation: >
      Hapus 'harga' dari $fillable. Harga harus diatur hanya melalui
      panel admin atau logic bisnis yang terkontrol di service class.

  - id: ECOM-002
    name: "Checkout tanpa Validasi Stok"
    severity: high
    confidence: medium
    scanner: controller
    description: >
      Method checkout() tidak memvalidasi ketersediaan stok sebelum
      memproses pembayaran.
    pattern:
      type: php_method
      class_pattern: "*CheckoutController"
      methods: ["store", "process", "checkout"]
      missing_calls:
        - "stok"
        - "stock"
        - "available"
        - "qty"
    remediation: >
      Periksa stok produk sebelum checkout:
      abort_if($produk->stok < $qty, 422, 'Stok tidak mencukupi');
```

### Lokasi File Aturan

```
rules/
├── default/              # Aturan bawaan Waskita (jangan diubah)
│   ├── mass-assignment-rules.yaml
│   ├── idor-rules.yaml
│   ├── xss-rules.yaml
│   ├── sqli-rules.yaml
│   ├── csrf-rules.yaml
│   ├── env-rules.yaml
│   ├── headers-rules.yaml
│   └── ratelimit-rules.yaml
└── custom/               # Aturan kustom proyek Anda
    ├── bisnis-rules.yaml
    └── compliance-rules.yaml
```

---

## Troubleshooting & FAQ

### ❓ Q: Saya menjalankan `php artisan waskita:audit` tetapi mendapat error "Command not found"
**A:** Pastikan package sudah terinstal dan service provider sudah terdaftar:
```bash
composer require --dev waskita/security
php artisan list | grep waskita
```
Jika menggunakan Laravel < 11 tanpa auto-discovery, daftarkan manual di `config/app.php`:
```php
'providers' => [
    Waskita\Security\WaskitaServiceProvider::class,
],
```

### ❓ Q: Bagaimana cara mengabaikan (ignore) temuan tertentu yang merupakan false positive?
**A:** Tambahkan komentar `@waskita-ignore RULE-ID` pada baris kode:
```php
protected $guarded = []; // @waskita-ignore MA-001 — ini pivot table tanpa user input
```

### ❓ Q: Apakah Waskita memperlambat aplikasi di production?
**A:** Tidak. Waskita diinstal sebagai `require-dev` dan hanya digunakan saat development dan CI. Package ini **tidak** dimuat di production environment (`--no-dev`).

### ❓ Q: Bisakah saya mengaudit proyek Laravel lama (versi 8, 9, 10)?
**A:** Ya. Gunakan pendekatan standalone (Git Clone) dan arahkan ke direktori proyek target:
```bash
php artisan waskita:audit --path=/path/ke/proyek-laravel-lama
```

### ❓ Q: Bagaimana cara menambahkan pengecekan Security Headers pada server production tanpa menginstal apapun?
**A:** Gunakan perintah `waskita:headers` yang melakukan pemeriksaan via HTTP request langsung:
```bash
php artisan waskita:headers https://domain-production.com
```

### ❓ Q: Bagaimana menjalankan audit hanya untuk kategori tertentu?
**A:** Gunakan flag `--category`:
```bash
php artisan waskita:audit --category=idor,xss,mass-assignment
```

### ❓ Q: Apakah saya bisa mengintegrasikan Waskita dengan GitLab CI?
**A:** Ya. Prinsipnya sama dengan GitHub Actions — jalankan perintah audit di tahap CI dan gunakan exit code untuk menentukan keberhasilan pipeline:
```yaml
# .gitlab-ci.yml
security_audit:
  stage: test
  script:
    - composer install --prefer-dist --no-progress
    - php artisan waskita:audit --fail-on=high
```

---

> **Dokumen ini ditulis untuk versi Waskita v1.0.0.**  
> Untuk pertanyaan atau kontribusi, silakan buka issue di [GitHub Repository](https://github.com/waskita/security).
