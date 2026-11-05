<?php

declare(strict_types=1);

namespace Waskita\Security\Scanners;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\ScannerInterface;

/**
 * SqlInjectionScanner - Mendeteksi potensi kerentanan SQL Injection pada kode Laravel.
 *
 * Pemeriksaan:
 * 1. Raw queries (DB::raw, whereRaw, selectRaw, dll) dengan konkatenasi string atau variabel interpolasi tanpa parameter binding.
 * 2. orderBy() yang menggunakan $request->input(...) tanpa validasi whitelist (in_array).
 * 3. DB::statement() / DB::unprepared() dengan konkatenasi input.
 */
class SqlInjectionScanner implements ScannerInterface
{
    /** @var string[] Raw query methods di Eloquent / Query Builder */
    private const RAW_METHODS = [
        'DB::raw',
        'whereRaw',
        'orWhereRaw',
        'havingRaw',
        'orHavingRaw',
        'orderByRaw',
        'groupByRaw',
        'selectRaw',
        'DB::select',
        'DB::statement',
        'DB::unprepared',
    ];

    public function getName(): string
    {
        return 'SQL Injection Scanner';
    }

    public function getDescription(): string
    {
        return 'Mendeteksi celah SQL Injection pada query Eloquent/DB: raw query dengan konkatenasi string, interpolasi variabel tanpa binding, dan orderBy dinamis tanpa whitelist.';
    }

    public function scan(string $basePath, array $config = []): array
    {
        $results = [];

        // Scan semua file PHP di bawah app/ (Controllers, Models, Services, Repositories, dll)
        $appDir = $basePath . '/app';
        $phpFiles = $this->findPhpFiles($appDir);

        foreach ($phpFiles as $file) {
            $results = array_merge($results, $this->scanPhpFile($file, $basePath));
        }

        return $results;
    }

    /**
     * Scan satu file PHP untuk potensi SQL Injection.
     *
     * @return AuditResult[]
     */
    private function scanPhpFile(string $filePath, string $basePath): array
    {
        $results = [];
        $content = (string) file_get_contents($filePath);
        $relativePath = $this->getRelativePath($filePath, $basePath);
        $lines = explode("\n", $content);

        // 1. Audit Raw Query Methods
        $results = array_merge($results, $this->scanRawQueries($content, $relativePath, $lines));

        // 2. Audit orderBy() dengan request parameter tanpa whitelist
        $results = array_merge($results, $this->scanUnvalidatedOrderBy($content, $relativePath, $lines));

        return $results;
    }

    /**
     * Scan raw queries dengan interpolasi variabel atau konkatenasi.
     *
     * @return AuditResult[]
     */
    private function scanRawQueries(string $content, string $relativePath, array $lines): array
    {
        $results = [];

        foreach (self::RAW_METHODS as $method) {
            // Regex mencari pemanggilan method: ->whereRaw(...) atau DB::raw(...)
            $escapedMethod = preg_quote($method, '/');
            // Menangkap signature: DB::raw(...) atau ->whereRaw(...)
            $pattern = '/(?:->|::)?' . $escapedMethod . '\s*\(([^;]+?)\)(?:\s*;|\s*->)/s';

            if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $i => $match) {
                    $argsString = $matches[1][$i][0];
                    $offset = $match[1];
                    $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
                    $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                    // Cek apakah ada interpolasi variabel atau konkatenasi string di argumen pertama
                    $hasConcatenation = $this->hasStringConcatenation($argsString);
                    $hasInterpolation = $this->hasVariableInterpolation($argsString);
                    $hasBindings = $this->hasParameterBindings($argsString);

                    if (($hasConcatenation || $hasInterpolation) && ! $hasBindings) {
                        $reason = $hasConcatenation ? 'konkatenasi string (.)' : 'interpolasi variabel ($)';

                        $results[] = new AuditResult(
                            ruleId: 'SQLI_RAW_QUERY_CONCATENATION',
                            category: 'sql_injection',
                            severity: AuditResult::SEVERITY_CRITICAL,
                            title: "SQL Injection: Unsafe {$method}() with Variable {$reason}",
                            description: "Ditemukan pemanggilan {$method}() yang menggabungkan variabel langsung ke dalam string query SQL tanpa parameter bindings. Penyerang dapat memanipulasi struktur query SQL.",
                            file: $relativePath,
                            line: $lineNumber,
                            codeSnippet: $snippet,
                            suggestion: "Gunakan parameter binding (tanda tanya ? atau named binding): {$method}('column = ?', [\$value]).",
                            cveRef: 'CWE-89'
                        );
                    }
                }
            }
        }

        return $results;
    }

    /**
     * Cek apakah ada konkatenasi string (titik di luar string) di dalam ekspresi query.
     */
    private function hasStringConcatenation(string $args): bool
    {
        // Pisahkan argumen pertama (query string)
        $firstArg = $this->extractFirstArgument($args);

        // Cari pola konkatenasi: . $var atau $var . atau . request()
        if (preg_match('/(?:["\']\s*\.\s*\$|\$\w+\s*\.\s*["\']|\.\s*(?:\$request|request\(|\$id|\$input))/i', $firstArg)) {
            return true;
        }

        // sprintf("... %s ...", $var)
        if (str_contains($firstArg, 'sprintf(')) {
            return true;
        }

        return false;
    }

    /**
     * Cek apakah ada interpolasi variabel di dalam string tanda petik ganda.
     */
    private function hasVariableInterpolation(string $args): bool
    {
        $firstArg = $this->extractFirstArgument($args);

        // Cari string petik ganda yang mengandung $var atau {$var}
        if (preg_match('/"([^"]*(?:\$\w+|\{\$\w+\})[^"]*)"/', $firstArg)) {
            return true;
        }

        return false;
    }

    /**
     * Cek apakah query memiliki parameter binding sebagai argumen kedua.
     * Contoh: whereRaw('status = ?', [$status]) atau orderByRaw($expr, $bindings)
     */
    private function hasParameterBindings(string $args): bool
    {
        // 1. Literal array binding: whereRaw('status = ?', [$status])
        $hasArrayBinding = (bool) preg_match('/,\s*\[/i', $args);
        $hasQuestionMark = str_contains($args, '?') || str_contains($args, ':');

        if ($hasArrayBinding && $hasQuestionMark) {
            return true;
        }

        // 2. Variable binding sebagai argumen kedua: orderByRaw($stmt, $bindings)
        $hasVariableBinding = (bool) preg_match('/,\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*/', $args);
        if ($hasVariableBinding) {
            return true;
        }

        return false;
    }

    /**
     * Ekstrak argumen pertama dari daftar argumen fungsi.
     */
    private function extractFirstArgument(string $args): string
    {
        // Sederhanakan: ambil string hingga koma pertama di luar tanda kurung/petik
        $inQuote = false;
        $quoteChar = '';
        $len = strlen($args);

        for ($i = 0; $i < $len; $i++) {
            $char = $args[$i];

            if (($char === '"' || $char === "'") && ($i === 0 || $args[$i - 1] !== '\\')) {
                if (! $inQuote) {
                    $inQuote = true;
                    $quoteChar = $char;
                } elseif ($quoteChar === $char) {
                    $inQuote = false;
                }
            }

            if ($char === ',' && ! $inQuote) {
                return substr($args, 0, $i);
            }
        }

        return $args;
    }

    /**
     * Scan orderBy($request->input(...)) atau orderBy($sort) tanpa whitelist in_array.
     *
     * @return AuditResult[]
     */
    private function scanUnvalidatedOrderBy(string $content, string $relativePath, array $lines): array
    {
        $results = [];

        // Pola: ->orderBy($request->input('sort')) atau ->orderBy($request->get('by')) atau ->orderBy(request('sort'))
        $pattern = '/->orderBy\s*\(\s*(?:\$request->(?:input|get|query)\([\'"]\w+[\'"]\)|request\([\'"]\w+[\'"]\))\s*(?:,\s*[^)]+)?\)/i';

        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $offset = $match[1];
                $lineNumber = substr_count(substr($content, 0, $offset), "\n") + 1;
                $snippet = trim($lines[$lineNumber - 1] ?? $match[0]);

                // Periksa apakah ada in_array di sekitar (5 baris sebelumnya)
                $contextStart = max(0, $lineNumber - 5);
                $context = implode("\n", array_slice($lines, $contextStart, 6));

                if (! str_contains($context, 'in_array(')) {
                    $results[] = new AuditResult(
                        ruleId: 'SQLI_ORDER_BY_USER_INPUT',
                        category: 'sql_injection',
                        severity: AuditResult::SEVERITY_HIGH,
                        title: 'Potential SQL Injection: Unvalidated orderBy() Column',
                        description: 'orderBy() menerima nama kolom langsung dari user input tanpa validasi whitelist (in_array). Penyerang dapat menginjeksi ekspresi SQL atau boolean-based blind SQL injection.',
                        file: $relativePath,
                        line: $lineNumber,
                        codeSnippet: $snippet,
                        suggestion: "Validasi kolom dengan whitelist sebelum query: \$sort = in_array(\$request->sort, ['name', 'created_at', 'price']) ? \$request->sort : 'id';",
                        cveRef: 'CWE-89'
                    );
                }
            }
        }

        return $results;
    }

    /**
     * @return string[]
     */
    private function findPhpFiles(string $dir): array
    {
        if (! is_dir($dir)) {
            return [];
        }

        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
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
