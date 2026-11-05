<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * XssScanner - Mendeteksi kerentanan Cross-Site Scripting (XSS) di Blade templates.
 *
 * Pemeriksaan:
 * 1. Unescaped blade echo {!! ... !!} tanpa sanitasi (HTMLPurifier, e(), htmlspecialchars)
 * 2. Unescaped echo dengan user input langsung ($request, $_GET, $_POST, $input)
 * 3. Dangerous JavaScript attribute contexts: href="javascript:", onclick, onload, onerror
 * 4. Rekomendasi CSP (Content-Security-Policy) di layout views
 */
class XssScanner implements ScannerInterface
{
    /** @var string[] Variabel yang mengandung user input */
    private const USER_INPUT_PATTERNS = [
        '$request->',
        'request()->',
        'request(',
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$input',
        '$query',
    ];

    /** @var string[] Fungsi sanitasi yang aman */
    private const SANITIZER_PATTERNS = [
        'Purifier::clean(',
        'clean(',
        'htmlspecialchars(',
        'htmlentities(',
        'e(',
        'strip_tags(',
        'Str::of(',
    ];

    /** @var string[] Event handler attributes berbahaya */
    private const DANGEROUS_ATTRIBUTES = [
        'onclick',
        'onload',
        'onerror',
        'onmouseover',
        'onmouseenter',
        'onfocus',
        'onblur',
        'onsubmit',
        'onchange',
        'oninput',
    ];

    public function getName(): string
    {
        return 'XSS Scanner';
    }

    public function getDescription(): string
    {
        return 'Mendeteksi kerentanan Cross-Site Scripting (XSS) di Blade templates: unescaped echo, user input langsung, JavaScript injection context.';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        // 1. Scan semua Blade templates
        $bladeFiles = $this->findBladeFiles($basePath . '/resources/views');
        foreach ($bladeFiles as $file) {
            $results = array_merge($results, $this->scanBladeFile($file, $basePath));
        }

        // 2. Cek CSP di layout views
        $results = array_merge($results, $this->checkCspInLayouts($bladeFiles, $basePath));

        return $results;
    }

    /**
     * Scan satu file Blade template untuk XSS vulnerabilities.
     *
     * @return AuditResult[]
     */
    private function scanBladeFile(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // 1. Deteksi {!! ... !!} (unescaped blade echo)
        $pattern = '/\{!!\s*(.+?)\s*!!\}/s';
        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $i => $match) {
                $fullMatch = $match[0];
                $innerContent = $matches[1][$i][0];
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
                $snippet = trim($lines[$lineNumber - 1] ?? $fullMatch);

                // Cek apakah mengandung user input langsung
                $hasUserInput = $this->containsUserInput($innerContent);
                // Cek apakah sudah disanitasi
                $isSanitized = $this->isSanitized($innerContent);

                if ($hasUserInput && ! $isSanitized) {
                    // CRITICAL: user input langsung di-echo tanpa sanitasi
                    $results[] = new AuditResult(
                        ruleId: 'XSS_UNESCAPED_USER_INPUT',
                        category: 'xss',
                        severity: AuditResult::SEVERITY_CRITICAL,
                        title: 'Reflected XSS: Direct Unescaped Output of User Input',
                        description: "Ditemukan {!! ... !!} yang langsung mencetak user input tanpa sanitasi. Penyerang bisa menyisipkan tag <script> melalui parameter request.",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Gunakan {{ ... }} untuk auto-escaping, atau e(\$var) / Purifier::clean(\$var) untuk sanitasi manual.",
                        cveRef: 'CWE-79'
                    );
                } elseif (! $isSanitized) {
                    // MEDIUM: unescaped echo tanpa sanitasi (bisa jadi stored XSS)
                    $results[] = new AuditResult(
                        ruleId: 'XSS_RAW_BLADE_ECHO',
                        category: 'xss',
                        severity: AuditResult::SEVERITY_MEDIUM,
                        title: 'Raw Blade Echo Without Sanitization: {!! ... !!}',
                        description: "Tag {!! ... !!} tidak melakukan HTML escaping. Jika variabel berasal dari database (user-generated content) yang tidak disanitasi saat penyimpanan, Stored XSS mungkin terjadi.",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Gunakan {{ ... }} untuk auto-escaping, atau gunakan Purifier::clean(\$var) sebelum mencetak HTML.",
                        cveRef: 'CWE-79'
                    );
                }
            }
        }

        // 2. Deteksi JavaScript contexts berbahaya
        $results = array_merge($results, $this->scanDangerousJsContexts($content, $relativePath, $lines));

        return $results;
    }

    /**
     * Deteksi penggunaan blade echo di dalam JavaScript attribute contexts.
     *
     * @return AuditResult[]
     */
    private function scanDangerousJsContexts(string $content, string $relativePath, array $lines): array
    {
        $results = [];

        // Pattern 1: href="javascript:{!! ... !!}" atau href="javascript:{{ ... }}"
        // Bounded strictly inside quotes to prevent multiline regex overrun
        $jsHrefPattern = '/href\s*=\s*(["\'])javascript\s*:(?:(?!\1).)*(?:\{\{.*?\}\}|\{!!.*?!!\})(?:(?!\1).)*\1/i';
        if (preg_match_all($jsHrefPattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
                $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                $results[] = new AuditResult(
                    ruleId: 'XSS_JAVASCRIPT_HREF',
                    category: 'xss',
                    severity: AuditResult::SEVERITY_HIGH,
                    title: 'XSS via href="javascript:..." with Dynamic Content',
                    description: "Blade echo di dalam href=\"javascript:...\" dapat dieksploitasi untuk XSS. htmlspecialchars() tidak memberikan perlindungan dalam konteks JavaScript URI.",
                    file: $relativePath,
                    line: $lineNumber,
                    codeSnippet: $snippet,
                    suggestion: "Hindari href=\"javascript:...\". Gunakan event listener terpisah di file JS atau validasi URL secara ketat.",
                    cveRef: 'CWE-79'
                );
            }
        }

        // Pattern 2: Event handler attributes (onclick, onload, dll) dengan blade echo
        // Bounded strictly inside quotes to prevent false positives on static JavaScript
        foreach (self::DANGEROUS_ATTRIBUTES as $attr) {
            $eventPattern = '/' . preg_quote($attr, '/') . '\s*=\s*(["\'])(?:(?!\1).)*(?:\{\{.*?\}\}|\{!!.*?!!\})(?:(?!\1).)*\1/i';
            if (preg_match_all($eventPattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $offset = $match[1];
                    $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
                    $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                    $results[] = new AuditResult(
                        ruleId: 'XSS_DANGEROUS_JS_ATTRIBUTE',
                        category: 'xss',
                        severity: AuditResult::SEVERITY_HIGH,
                        title: "XSS: Dynamic Content in '{$attr}' Event Handler",
                        description: "Blade echo di dalam atribut event handler ({$attr}) rentan XSS. Auto-escaping {{ }} tidak cukup untuk konteks JavaScript.",
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Gunakan @js() directive untuk encoding JS di Blade, atau pindahkan logic ke event listener terpisah.",
                        cveRef: 'CWE-79'
                    );
                }
            }
        }

        return $results;
    }

    /**
     * Cek apakah layout view mengandung Content-Security-Policy.
     *
     * @param string[] $bladeFiles
     * @return AuditResult[]
     */
    private function checkCspInLayouts(array $bladeFiles, string $basePath): array
    {
        $layoutFiles = array_filter($bladeFiles, function (string $file) {
            $basename = basename($file, '.blade.php');
            return in_array($basename, ['app', 'master', 'main', 'layout', 'base'], true)
                || str_contains($file, 'layouts/');
        });

        // Jika tidak ada layout files, skip
        if (empty($layoutFiles)) {
            return [];
        }

        $hasCsp = false;
        foreach ($layoutFiles as $file) {
            $content = (string) file_get_contents($file);
            if (preg_match('/content-security-policy/i', $content) ||
                str_contains($content, 'csp-nonce') ||
                str_contains($content, '@csp')) {
                $hasCsp = true;
                break;
            }
        }

        if (! $hasCsp) {
            return [
                new AuditResult(
                    ruleId: 'XSS_MISSING_CSP_META',
                    category: 'xss',
                    severity: AuditResult::SEVERITY_LOW,
                    title: 'Missing Content-Security-Policy in Layout Views',
                    description: "Tidak ditemukan tag meta Content-Security-Policy atau directive @csp di layout view. CSP membantu mencegah eksekusi script yang tidak diotorisasi.",
                    file: 'resources/views/layouts/',
                    suggestion: "Tambahkan <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self'\"> atau gunakan middleware/package CSP.",
                    cveRef: 'CWE-1021'
                ),
            ];
        }

        return [];
    }

    /**
     * Cek apakah ekspresi mengandung user input.
     */
    private function containsUserInput(string $expression): bool
    {
        foreach (self::USER_INPUT_PATTERNS as $pattern) {
            if (str_contains($expression, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Cek apakah ekspresi sudah disanitasi.
     */
    private function isSanitized(string $expression): bool
    {
        foreach (self::SANITIZER_PATTERNS as $pattern) {
            if (str_contains($expression, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Cari semua file .blade.php rekursif.
     *
     * @return string[]
     */
    private function findBladeFiles(string $dir): array
    {
        if (! is_dir($dir)) {
            return [];
        }

        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && str_ends_with($file->getFilename(), '.blade.php')) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function getRelativePath(string $fullPath, string $basePath): string
    {
        $base = rtrim($basePath, '/') . '/';
        if (str_starts_with($fullPath, $base)) {
            return substr($fullPath, strlen($base));
        }

        return $fullPath;
    }
}
