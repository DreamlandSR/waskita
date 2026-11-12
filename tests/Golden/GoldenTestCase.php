<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use PHPUnit\Framework\TestCase;
use Waskita\Security\Core\AuditResult;

/**
 * GoldenTestCase - Base class untuk Golden Tests (fixture-based scanner tests).
 *
 * Menyediakan helper untuk membuat/menghapus temporary fixture directories
 * dan assertion khusus untuk memverifikasi scanner findings.
 */
abstract class GoldenTestCase extends TestCase
{
    /** @var string[] Daftar fixture directories yang dibuat selama test */
    private array $fixtureDirs = [];

    /**
     * Buat temporary fixture directory dengan nama unik.
     */
    protected function createFixtureDir(): string
    {
        $dir = sys_get_temp_dir() . '/waskita_golden_' . uniqid('', true);
        if (!mkdir($dir, 0777, true) && !is_dir($dir)) {
            $this->fail("Failed to create fixture directory: {$dir}");
        }
        $this->fixtureDirs[] = $dir;

        return $dir;
    }

    /**
     * Hapus fixture directory secara rekursif.
     */
    protected function cleanupFixtureDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
            } else {
                unlink($item->getPathname());
            }
        }

        rmdir($dir);
    }

    /**
     * Buat file fixture di dalam base directory. Membuat subdirectories secara otomatis.
     */
    protected function createFixtureFile(string $baseDir, string $relativePath, string $content): string
    {
        $fullPath = $baseDir . '/' . $relativePath;
        $parentDir = dirname($fullPath);

        if (!is_dir($parentDir)) {
            mkdir($parentDir, 0777, true);
        }

        file_put_contents($fullPath, $content);

        return $fullPath;
    }

    /**
     * Assert bahwa hasil scan mengandung setidaknya satu finding dengan ruleId tertentu.
     *
     * @param AuditResult[] $results
     */
    protected function assertMustFlag(array $results, string $ruleId, ?string $severity = null): void
    {
        $found = false;
        $foundRules = [];

        foreach ($results as $result) {
            $foundRules[] = $result->ruleId . ' (' . $result->severity . ')';
            if ($result->ruleId === $ruleId) {
                if ($severity === null || $result->severity === $severity) {
                    $found = true;
                    break;
                }
            }
        }

        $message = "Expected scanner to flag '{$ruleId}'";
        if ($severity !== null) {
            $message .= " with severity '{$severity}'";
        }
        $message .= ". Found rules: [" . implode(', ', $foundRules) . "]";

        $this->assertTrue($found, $message);
    }

    /**
     * Assert bahwa hasil scan tidak mengandung finding dengan ruleId tertentu.
     *
     * @param AuditResult[] $results
     */
    protected function assertMustNotFlag(array $results, string $ruleId): void
    {
        foreach ($results as $result) {
            if ($result->ruleId === $ruleId) {
                $this->fail("Expected scanner NOT to flag '{$ruleId}', but it did: {$result->title}");
            }
        }

        $this->assertTrue(true);
    }

    /**
     * Assert bahwa hasil scan kosong (tidak ada finding).
     *
     * @param AuditResult[] $results
     */
    protected function assertMustPass(array $results, string $message = ''): void
    {
        if ($message === '') {
            $foundRules = array_map(
                fn(AuditResult $r) => $r->ruleId . ' (' . $r->severity . '): ' . $r->title,
                $results
            );
            $message = "Expected scanner to produce no findings, but found:\n" . implode("\n", $foundRules);
        }

        $this->assertEmpty($results, $message);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixtureDirs = [];
    }

    protected function tearDown(): void
    {
        foreach ($this->fixtureDirs as $dir) {
            $this->cleanupFixtureDir($dir);
        }
        $this->fixtureDirs = [];
        parent::tearDown();
    }
}
