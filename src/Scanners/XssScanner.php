<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\LaravelSecurityDictionary;
use Waskita\Security\Core\ScannerInterface;

/**
 * XssScanner - Mendeteksi kerentanan Cross-Site Scripting (XSS) di Blade templates.
 *
 * Pemeriksaan:
 * 1. Unescaped blade echo {!! ... !!} tanpa sanitasi (HTMLPurifier, e(), htmlspecialchars)
 * 2. Unescaped echo dengan user input langsung ($request, $_GET, $_POST, $input)
 * 3. Dangerous JavaScript attribute contexts: href="javascript:", onclick, onload, onerror
 */
class XssScanner implements ScannerInterface
{
    /** @var array<string, array<string, string>> Cache model files per basePath */
    private array $modelCache = [];

    /** @var string[] Variabel yang mengandung user input */
    private const USER_INPUT_PATTERNS = LaravelSecurityDictionary::USER_INPUT_SOURCES;

    /** @var string[] Fungsi sanitasi yang aman */
    private const SANITIZER_PATTERNS = LaravelSecurityDictionary::XSS_SANITIZERS;

    /** @var string[] Default helper/callable yang aman untuk render SVG/HTML internal */
    private const DEFAULT_SAFE_CALLABLES = LaravelSecurityDictionary::DEFAULT_SAFE_VIEW_HELPERS;

    /** @var string[] Event handler attributes berbahaya */
    private const DANGEROUS_ATTRIBUTES = LaravelSecurityDictionary::DANGEROUS_HTML_ATTRIBUTES;

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
            $results = array_merge($results, $this->scanBladeFile($file, $basePath, $config));
        }

        return $results;
    }

    /**
     * Scan satu file Blade template untuk XSS vulnerabilities.
     *
     * @param array<string, mixed> $config
     * @return AuditResult[]
     */
    private function scanBladeFile(string $filePath, string $basePath, array $config = []): array
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
                } elseif (
                    ! $isSanitized
                    && ! $this->isStaticLiteral($innerContent)
                    && ! $this->isSafeCallableOrPattern($innerContent, $config)
                    && ! $this->isAccessorSanitized($innerContent, $basePath)
                ) {
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
     * Cek apakah ekspresi mengakses Eloquent accessor yang melakukan sanitasi.
     */
    private function isAccessorSanitized(string $expression, string $basePath): bool
    {
        // Ekstrak property name dari pola seperti $var->property_name atau $var?->property_name
        if (! preg_match_all('/(?:->|\?->)\s*([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\b(?!\s*\()/m', $expression, $matches)) {
            return false;
        }

        $properties = array_unique($matches[1]);
        if (empty($properties)) {
            return false;
        }

        $modelFiles = $this->getModelFiles($basePath);
        if (empty($modelFiles)) {
            return false;
        }

        foreach ($properties as $prop) {
            // Konversi snake_case / camelCase ke PascalCase
            $pascal = str_replace(' ', '', ucwords(str_replace(['-', '_'], ' ', $prop)));
            $accessorName = 'get' . $pascal . 'Attribute';
            $camel = lcfirst($pascal);

            foreach ($modelFiles as $filePath => $modelContent) {
                // 1. Cek traditional Eloquent accessor: get{Property}Attribute
                if (stripos($modelContent, $accessorName) !== false) {
                    $pattern = '/function\s+' . preg_quote($accessorName, '/') . '\s*\([^)]*\)/i';
                    if (preg_match($pattern, $modelContent, $fnMatch, PREG_OFFSET_CAPTURE)) {
                        $offset = (int) $fnMatch[0][1];
                        $body = $this->extractMethodBody($modelContent, $offset);
                        if ($body !== null && $this->methodAppliesSanitization($body, $modelContent)) {
                            return true;
                        }
                    }
                }

                // 2. Cek Laravel 9+ Attribute accessor: function {property}(): Attribute
                if (stripos($modelContent, $camel) !== false) {
                    $pattern = '/function\s+' . preg_quote($camel, '/') . '\s*\([^)]*\)\s*:\s*Attribute\b/i';
                    if (preg_match($pattern, $modelContent, $fnMatch, PREG_OFFSET_CAPTURE)) {
                        $offset = (int) $fnMatch[0][1];
                        $body = $this->extractMethodBody($modelContent, $offset);
                        if ($body !== null && $this->methodAppliesSanitization($body, $modelContent)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    /**
     * Cek apakah method body atau helper internal yang dipanggilnya melakukan sanitasi.
     */
    private function methodAppliesSanitization(string $body, string $modelContent): bool
    {
        if ($this->isSanitized($body)) {
            return true;
        }

        // Cek apakah method mendelegasikan ke internal helper: self::helper(), $this->helper(), static::helper()
        if (preg_match_all('/(?:self::|\$this->|static::)\s*([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\(/i', $body, $calls)) {
            foreach (array_unique($calls[1]) as $helperName) {
                $pattern = '/function\s+' . preg_quote($helperName, '/') . '\s*\([^)]*\)/i';
                if (preg_match($pattern, $modelContent, $fnMatch, PREG_OFFSET_CAPTURE)) {
                    $offset = (int) $fnMatch[0][1];
                    $helperBody = $this->extractMethodBody($modelContent, $offset);
                    if ($helperBody !== null && $this->isSanitized($helperBody)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Ambil semua file model PHP beserta kontennya dengan caching.
     *
     * @return array<string, string> File path => file content
     */
    private function getModelFiles(string $basePath): array
    {
        $normalizedPath = rtrim($basePath, '/\\');
        if (isset($this->modelCache[$normalizedPath])) {
            return $this->modelCache[$normalizedPath];
        }

        $models = [];

        // 1. Laravel 8+ style: app/Models/
        $modelsDir = $normalizedPath . '/app/Models';
        if (is_dir($modelsDir)) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($modelsDir, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $file) {
                if ($file->isFile() && str_ends_with($file->getFilename(), '.php')) {
                    $models[$file->getPathname()] = (string) file_get_contents($file->getPathname());
                }
            }
        }

        // 2. Flat style: app/*.php
        $appDir = $normalizedPath . '/app';
        if (is_dir($appDir)) {
            $flatFiles = glob($appDir . '/*.php') ?: [];
            foreach ($flatFiles as $file) {
                if (is_file($file)) {
                    $models[$file] = (string) file_get_contents($file);
                }
            }
        }

        $this->modelCache[$normalizedPath] = $models;

        return $this->modelCache[$normalizedPath];
    }

    /**
     * Ekstrak body method dari opening brace ke closing brace.
     */
    private function extractMethodBody(string $content, int $offset): ?string
    {
        $braceStart = strpos($content, '{', $offset);
        if ($braceStart === false) {
            return null;
        }

        $depth = 0;
        $len = strlen($content);
        for ($i = $braceStart; $i < $len; $i++) {
            if ($content[$i] === '{') {
                $depth++;
            } elseif ($content[$i] === '}') {
                $depth--;
                if ($depth === 0) {
                    return substr($content, $braceStart, $i - $braceStart + 1);
                }
            }
        }

        return null;
    }

    /**
     * Cek apakah ekspresi mengandung user input.
     */
    private function containsUserInput(string $expression): bool
    {
        return LaravelSecurityDictionary::containsUserInput($expression);
    }

    /**
     * Cek apakah ekspresi sudah disanitasi.
     */
    private function isSanitized(string $expression): bool
    {
        return LaravelSecurityDictionary::isSanitized($expression);
    }

    /**
     * Cek apakah ekspresi merupakan pemanggilan method/helper yang terdaftar aman atau sesuai pattern konfigurasi.
     *
     * @param array<string, mixed> $config
     */
    private function isSafeCallableOrPattern(string $expression, array $config): bool
    {
        return LaravelSecurityDictionary::isSafeViewHelper($expression, $config);
    }

    /**
     * Cek apakah ekspresi bernilai statis murni / tanpa variabel dinamis ($).
     * Ekspresi tanpa variabel dan tanpa user input tidak mungkin dieksploitasi untuk XSS.
     */
    private function isStaticLiteral(string $expression): bool
    {
        return LaravelSecurityDictionary::isStaticLiteral($expression);
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
