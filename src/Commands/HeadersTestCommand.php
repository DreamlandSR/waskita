<?php

declare(strict_types=1);

namespace Waskita\Security\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

/**
 * Test security headers of a live endpoint.
 *
 * Sends an HTTP GET request, inspects response headers, and reports
 * pass/fail status for each recommended security header together
 * with actionable recommendations.
 */
class HeadersTestCommand extends Command
{
    /** @var string */
    protected $signature = 'waskita:headers
        {url? : Target URL to test (defaults to APP_URL)}';

    /** @var string */
    protected $description = 'Test security headers of a live endpoint';

    /**
     * Required/recommended headers with descriptions and expected values.
     *
     * @var array<string, array{description: string, expected: string, recommendation: string}>
     */
    private const HEADER_CHECKS = [
        'Strict-Transport-Security' => [
            'description'    => 'HTTP Strict Transport Security (HSTS)',
            'expected'       => 'max-age=31536000; includeSubDomains',
            'recommendation' => 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        ],
        'Content-Security-Policy' => [
            'description'    => 'Content Security Policy (CSP)',
            'expected'       => "default-src 'self'",
            'recommendation' => "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'",
        ],
        'X-Frame-Options' => [
            'description'    => 'Clickjacking protection',
            'expected'       => 'DENY|SAMEORIGIN',
            'recommendation' => 'Add header: X-Frame-Options: DENY (or SAMEORIGIN if embedding is needed)',
        ],
        'X-Content-Type-Options' => [
            'description'    => 'MIME type sniffing prevention',
            'expected'       => 'nosniff',
            'recommendation' => 'Add header: X-Content-Type-Options: nosniff',
        ],
        'Referrer-Policy' => [
            'description'    => 'Referrer information control',
            'expected'       => 'strict-origin-when-cross-origin|no-referrer',
            'recommendation' => 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        ],
        'Permissions-Policy' => [
            'description'    => 'Browser feature permissions',
            'expected'       => 'geolocation=(), camera=(), microphone=()',
            'recommendation' => 'Add header: Permissions-Policy: geolocation=(), camera=(), microphone=()',
        ],
    ];

    /** ANSI helpers */
    private const GREEN  = "\033[32m";
    private const RED    = "\033[31m";
    private const YELLOW = "\033[33m";
    private const CYAN   = "\033[36m";
    private const BOLD   = "\033[1m";
    private const RESET  = "\033[0m";

    public function handle(): int
    {
        $url = $this->argument('url')
            ? (string) $this->argument('url')
            : (string) config('app.url', 'http://localhost');

        $this->newLine();
        $b = self::BOLD;
        $r = self::RESET;
        $c = self::CYAN;
        $this->line("{$b}{$c}  Waskita — Security Headers Test{$r}");
        $this->line("  Target: {$url}");
        $this->newLine();

        // ── Send request ────────────────────────────────────────
        try {
            $response = Http::timeout(15)
                ->withoutVerifying()
                ->withHeaders(['User-Agent' => 'Waskita-Agent/1.0'])
                ->get($url);
        } catch (\Throwable $e) {
            $this->error("  Failed to connect to {$url}: {$e->getMessage()}");
            return self::FAILURE;
        }

        $statusCode = $response->status();
        $this->line("  HTTP Status: {$statusCode}");
        $this->newLine();

        // ── Check headers ───────────────────────────────────────
        $headers = $response->headers();
        $passed  = 0;
        $failed  = 0;
        $warned  = 0;

        $this->line("{$b}  ┌─────────────────────────────┬────────┬─────────────────────────────────────┐{$r}");
        $this->line("{$b}  │ Header                      │ Status │ Value / Recommendation              │{$r}");
        $this->line("{$b}  ├─────────────────────────────┼────────┼─────────────────────────────────────┤{$r}");

        foreach (self::HEADER_CHECKS as $header => $meta) {
            $value = $this->getHeaderValue($headers, $header);

            if ($value !== null) {
                $pass = $this->evaluateHeader($header, $value, $meta['expected']);
                if ($pass) {
                    $status = self::GREEN . '  PASS ' . self::RESET;
                    $display = $this->truncate($value, 35);
                    $passed++;
                } else {
                    $status = self::YELLOW . '  WARN ' . self::RESET;
                    $display = $this->truncate($value . ' (weak)', 35);
                    $warned++;
                }
            } else {
                $status  = self::RED . '  FAIL ' . self::RESET;
                $display = $this->truncate($meta['recommendation'], 35);
                $failed++;
            }

            $headerPad  = str_pad($header, 27);
            $displayPad = str_pad($display, 35);
            $this->line("  │ {$headerPad} │{$status}│ {$displayPad} │");
        }

        $this->line("{$b}  └─────────────────────────────┴────────┴─────────────────────────────────────┘{$r}");
        $this->newLine();

        // ── Summary ─────────────────────────────────────────────
        $total = count(self::HEADER_CHECKS);
        $this->line("  Results: " . self::GREEN . "{$passed} passed" . self::RESET
            . " / " . self::YELLOW . "{$warned} warnings" . self::RESET
            . " / " . self::RED . "{$failed} failed" . self::RESET
            . " (out of {$total})");
        $this->newLine();

        // ── Recommendations ─────────────────────────────────────
        if ($failed > 0 || $warned > 0) {
            $this->line("{$b}  Recommendations:{$r}");
            foreach (self::HEADER_CHECKS as $header => $meta) {
                $value = $this->getHeaderValue($headers, $header);
                if ($value === null) {
                    $this->line(self::RED . "  ✖ {$header}: " . self::RESET . $meta['recommendation']);
                } elseif (! $this->evaluateHeader($header, $value, $meta['expected'])) {
                    $this->line(self::YELLOW . "  ⚠ {$header}: " . self::RESET . "Current: {$value}. " . $meta['recommendation']);
                }
            }
            $this->newLine();
        }

        return $failed > 0 ? self::FAILURE : self::SUCCESS;
    }

    /**
     * Get a header value case-insensitively.
     *
     * @param  array<string, list<string>>  $headers
     */
    private function getHeaderValue(array $headers, string $name): ?string
    {
        // Headers may be stored with varying case
        foreach ($headers as $key => $values) {
            if (strcasecmp($key, $name) === 0) {
                return $values[0] ?? null;
            }
        }

        return null;
    }

    /**
     * Evaluate whether a header value meets expected criteria.
     */
    private function evaluateHeader(string $header, string $value, string $expected): bool
    {
        // If expected contains | alternatives, any match passes
        $alternatives = explode('|', $expected);

        foreach ($alternatives as $alt) {
            if (stripos($value, trim($alt)) !== false) {
                return true;
            }
        }

        // Special case: HSTS must have a sufficient max-age
        if ($header === 'Strict-Transport-Security') {
            if (preg_match('/max-age=(\d+)/', $value, $m)) {
                return (int) $m[1] >= 86400; // at least 1 day
            }
        }

        return false;
    }

    /**
     * Truncate a string to a maximum length.
     */
    private function truncate(string $text, int $maxLen): string
    {
        if (mb_strlen($text) <= $maxLen) {
            return $text;
        }

        return mb_substr($text, 0, $maxLen - 3) . '...';
    }
}
