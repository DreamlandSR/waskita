<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Unit;

use Waskita\Security\Core\AuditEngine;
use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\RuleLoader;
use Waskita\Security\Core\RuleValidator;
use Waskita\Security\Core\ScannerInterface;
use Waskita\Security\Reports\AgentReportFormatter;
use Waskita\Security\Reports\ConsoleReportFormatter;
use Waskita\Security\Reports\JsonReportFormatter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * Unit tests for Waskita core scanners, engine, and report formatters.
 *
 * These tests use PHPUnit directly (no Laravel app) by injecting stub
 * scanners and mocking filesystem interactions.
 */
class ScannersTest extends TestCase
{
    // ─────────────────────────────────────────────────────────────
    //  AuditResult
    // ─────────────────────────────────────────────────────────────

    public function test_audit_result_to_array(): void
    {
        $result = new AuditResult(
            ruleId: 'TEST_RULE',
            category: 'testing',
            severity: AuditResult::SEVERITY_HIGH,
            title: 'Test Finding',
            description: 'A test finding for unit tests.',
            file: 'app/Http/Controllers/UserController.php',
            line: 42,
            codeSnippet: '$user->update($request->all());',
            suggestion: 'Use $request->validated() instead.',
            cveRef: 'CVE-2023-00001',
        );

        $array = $result->toArray();

        $this->assertSame('TEST_RULE', $array['rule_id']);
        $this->assertSame('testing', $array['category']);
        $this->assertSame('HIGH', $array['severity']);
        $this->assertSame('Test Finding', $array['title']);
        $this->assertSame('app/Http/Controllers/UserController.php', $array['file']);
        $this->assertSame(42, $array['line']);
        $this->assertSame('CVE-2023-00001', $array['cve_ref']);
    }

    public function test_audit_result_penalties(): void
    {
        $critical = new AuditResult('R1', 'cat', AuditResult::SEVERITY_CRITICAL, 'T', 'D');
        $high     = new AuditResult('R2', 'cat', AuditResult::SEVERITY_HIGH, 'T', 'D');
        $medium   = new AuditResult('R3', 'cat', AuditResult::SEVERITY_MEDIUM, 'T', 'D');
        $low      = new AuditResult('R4', 'cat', AuditResult::SEVERITY_LOW, 'T', 'D');
        $info     = new AuditResult('R5', 'cat', AuditResult::SEVERITY_INFO, 'T', 'D');

        $this->assertSame(25, $critical->getPenalty());
        $this->assertSame(15, $high->getPenalty());
        $this->assertSame(5, $medium->getPenalty());
        $this->assertSame(2, $low->getPenalty());
        $this->assertSame(0, $info->getPenalty());
    }

    public function test_audit_result_severity_helpers(): void
    {
        $result = new AuditResult('R', 'c', AuditResult::SEVERITY_CRITICAL, 'T', 'D');

        $this->assertTrue($result->isCritical());
        $this->assertFalse($result->isHigh());
        $this->assertFalse($result->isMedium());
        $this->assertFalse($result->isLow());
        $this->assertFalse($result->isInfo());
    }

    public function test_audit_result_json_serialization(): void
    {
        $result = new AuditResult('JSON_TEST', 'cat', AuditResult::SEVERITY_LOW, 'Json Test', 'Desc');
        $json   = json_encode($result);

        $this->assertNotFalse($json);

        $decoded = json_decode($json, true);
        $this->assertSame('JSON_TEST', $decoded['rule_id']);
        $this->assertSame('LOW', $decoded['severity']);
    }

    // ─────────────────────────────────────────────────────────────
    //  AuditEngine with stub scanners
    // ─────────────────────────────────────────────────────────────

    public function test_engine_runs_custom_scanners(): void
    {
        $finding = new AuditResult(
            ruleId: 'STUB_FINDING',
            category: 'stub',
            severity: AuditResult::SEVERITY_MEDIUM,
            title: 'Stub finding',
            description: 'Found by stub scanner.',
        );

        $scanner = $this->createStubScanner('StubScanner', [$finding]);
        $engine  = new AuditEngine([], [$scanner]);

        $results = $engine->run('/tmp/fake-project');

        $this->assertCount(1, $results);
        $this->assertSame('STUB_FINDING', $results[0]->ruleId);
    }

    public function test_engine_score_with_no_findings(): void
    {
        $emptyScanner = $this->createStubScanner('EmptyScanner', []);
        $engine = new AuditEngine([], [$emptyScanner]);
        $engine->run('/tmp/fake');

        $this->assertSame(100, $engine->calculateScore());
        $this->assertSame('A', $engine->getGrade());
    }

    public function test_engine_score_with_critical_finding(): void
    {
        $finding = new AuditResult('CRIT', 'sec', AuditResult::SEVERITY_CRITICAL, 'Critical', 'D');
        $scanner = $this->createStubScanner('CritScanner', [$finding]);
        $engine  = new AuditEngine([], [$scanner]);
        $engine->run('/tmp/fake');

        $this->assertSame(75, $engine->calculateScore());
    }

    public function test_engine_summary(): void
    {
        $findings = [
            new AuditResult('F1', 'cat', AuditResult::SEVERITY_CRITICAL, 'C', 'D'),
            new AuditResult('F2', 'cat', AuditResult::SEVERITY_HIGH, 'H', 'D'),
            new AuditResult('F3', 'cat', AuditResult::SEVERITY_MEDIUM, 'M', 'D'),
            new AuditResult('F4', 'cat', AuditResult::SEVERITY_LOW, 'L', 'D'),
            new AuditResult('F5', 'cat', AuditResult::SEVERITY_INFO, 'I', 'D'),
        ];

        $scanner = $this->createStubScanner('AllSeverities', $findings);
        $engine  = new AuditEngine([], [$scanner]);
        $engine->run('/tmp/fake');

        $summary = $engine->getSummary();

        $this->assertSame(5, $summary['total']);
        $this->assertSame(1, $summary['critical']);
        $this->assertSame(1, $summary['high']);
        $this->assertSame(1, $summary['medium']);
        $this->assertSame(1, $summary['low']);
        $this->assertSame(1, $summary['info']);
    }

    public function test_engine_group_by_severity(): void
    {
        $findings = [
            new AuditResult('A', 'c', AuditResult::SEVERITY_HIGH, 'High1', 'D'),
            new AuditResult('B', 'c', AuditResult::SEVERITY_HIGH, 'High2', 'D'),
            new AuditResult('C', 'c', AuditResult::SEVERITY_LOW, 'Low1', 'D'),
        ];

        $scanner = $this->createStubScanner('GroupScanner', $findings);
        $engine  = new AuditEngine([], [$scanner]);
        $engine->run('/tmp/fake');

        $grouped = $engine->groupBySeverity();

        $this->assertCount(2, $grouped[AuditResult::SEVERITY_HIGH]);
        $this->assertCount(1, $grouped[AuditResult::SEVERITY_LOW]);
        $this->assertCount(0, $grouped[AuditResult::SEVERITY_CRITICAL]);
    }

    public function test_engine_handles_scanner_exception(): void
    {
        $failScanner = new class implements ScannerInterface {
            public function getName(): string { return 'FailScanner'; }
            public function getDescription(): string { return 'Always throws'; }
            public function scan(string $basePath, array $config = []): array
            {
                throw new \RuntimeException('Scanner failure');
            }
        };

        $engine = new AuditEngine([], [$failScanner]);
        $results = $engine->run('/tmp/fake');

        // Should produce an info-level internal error result
        $this->assertCount(1, $results);
        $this->assertSame('SCANNER_INTERNAL_ERROR', $results[0]->ruleId);
        $this->assertSame(AuditResult::SEVERITY_INFO, $results[0]->severity);
    }

    public function test_engine_scanner_filter(): void
    {
        $scannerA = $this->createStubScanner('AlphaScanner', [
            new AuditResult('A1', 'c', AuditResult::SEVERITY_LOW, 'AlphaFind', 'D'),
        ]);
        $scannerB = $this->createStubScanner('BetaScanner', [
            new AuditResult('B1', 'c', AuditResult::SEVERITY_LOW, 'BetaFind', 'D'),
        ]);

        $engine = new AuditEngine([], [$scannerA, $scannerB]);
        $results = $engine->run('/tmp/fake', ['Alpha']);

        $this->assertCount(1, $results);
        $this->assertSame('A1', $results[0]->ruleId);
    }

    // ─────────────────────────────────────────────────────────────
    //  RuleValidator
    // ─────────────────────────────────────────────────────────────

    public function test_rule_validator_passes_valid_rule(): void
    {
        $validator = new RuleValidator();

        $valid = $validator->validate([
            'id'       => 'test-rule-1',
            'name'     => 'Test Rule',
            'severity' => 'HIGH',
            'category' => 'testing',
        ]);

        $this->assertTrue($valid);
        $this->assertFalse($validator->hasErrors());
    }

    public function test_rule_validator_fails_missing_required(): void
    {
        $validator = new RuleValidator();

        $valid = $validator->validate([
            'id' => 'incomplete-rule',
            // missing name, severity, category
        ]);

        $this->assertFalse($valid);
        $this->assertTrue($validator->hasErrors());
        $this->assertGreaterThanOrEqual(3, count($validator->getErrors()));
    }

    public function test_rule_validator_fails_invalid_severity(): void
    {
        $validator = new RuleValidator();

        $valid = $validator->validate([
            'id'       => 'bad-severity',
            'name'     => 'Bad',
            'severity' => 'EXTREME',
            'category' => 'testing',
        ]);

        $this->assertFalse($valid);
    }

    // ─────────────────────────────────────────────────────────────
    //  RuleLoader
    // ─────────────────────────────────────────────────────────────

    public function test_rule_loader_returns_empty_for_missing_directory(): void
    {
        $loader = new RuleLoader();
        $rules  = $loader->loadFromDirectory('/nonexistent/path');

        $this->assertSame([], $rules);
    }

    public function test_rule_loader_reset(): void
    {
        $loader = new RuleLoader();
        // After reset, getRules should be empty
        $loader->reset();
        $this->assertSame([], $loader->getRules());
    }

    // ─────────────────────────────────────────────────────────────
    //  ConsoleReportFormatter
    // ─────────────────────────────────────────────────────────────

    public function test_console_formatter_renders_pass_with_no_findings(): void
    {
        $scanner = $this->createStubScanner('EmptyScanner', []);
        $engine  = new AuditEngine([], [$scanner]);
        $engine->run('/tmp/fake');

        $formatter = new ConsoleReportFormatter();
        $buffered  = new BufferedOutput();
        $passed    = $formatter->render($buffered, $engine, 'high', 0.0);

        $output = $buffered->fetch();

        $this->assertTrue($passed);
        $this->assertStringContainsString('PASS', $output);
        $this->assertStringContainsString('No security findings detected', $output);
    }

    public function test_console_formatter_renders_fail_with_critical(): void
    {
        $finding = new AuditResult('CRIT', 'sec', AuditResult::SEVERITY_CRITICAL, 'Critical Issue', 'Big problem');
        $scanner = $this->createStubScanner('CritScanner', [$finding]);
        $engine  = new AuditEngine([], [$scanner]);
        $engine->run('/tmp/fake');

        $formatter = new ConsoleReportFormatter();
        $buffered  = new BufferedOutput();
        $passed    = $formatter->render($buffered, $engine, 'high', 100.5);

        $output = $buffered->fetch();

        $this->assertFalse($passed);
        $this->assertStringContainsString('FAIL', $output);
        $this->assertStringContainsString('Critical Issue', $output);
    }

    public function test_engine_filters_waskita_ignore_annotation(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_test_' . uniqid();
        mkdir($tempDir, 0777, true);

        $testFile = $tempDir . '/test.php';
        file_put_contents($testFile, "<?php\n// @waskita-ignore SQLI\nDB::raw(\$query);\n");

        $finding = new AuditResult(
            ruleId: 'SQLI_RAW_QUERY_CONCATENATION',
            category: 'sql_injection',
            severity: AuditResult::SEVERITY_CRITICAL,
            title: 'SQL Injection',
            description: 'Unsafe raw query',
            file: 'test.php',
            line: 3,
        );

        $scanner = $this->createStubScanner('SqlScanner', [$finding]);
        $engine  = new AuditEngine([], [$scanner]);
        $results = $engine->run($tempDir);

        $this->assertSame([], $results, 'Finding should be ignored by @waskita-ignore annotation.');

        unlink($testFile);
        rmdir($tempDir);
    }

    public function test_engine_filters_blade_waskita_ignore_annotation(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_blade_ignore_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        // Case 1: same line specific ignore
        $file1 = $tempDir . '/resources/views/line1.blade.php';
        file_put_contents($file1, "<div>\n{!! \$val !!} {{-- @waskita-ignore XSS_RAW_BLADE_ECHO --}}\n</div>\n");

        // Case 2: same line blanket ignore
        $file2 = $tempDir . '/resources/views/line2.blade.php';
        file_put_contents($file2, "<div>\n{!! \$val !!} {{-- @waskita-ignore --}}\n</div>\n");

        // Case 3: preceding line with colon reason
        $file3 = $tempDir . '/resources/views/line3.blade.php';
        file_put_contents($file3, "<div>\n{{-- @waskita-ignore: alasan SVG aman --}}\n{!! \$val !!}\n</div>\n");

        $finding1 = new AuditResult('XSS_RAW_BLADE_ECHO', 'xss', AuditResult::SEVERITY_MEDIUM, 'XSS', 'D', 'resources/views/line1.blade.php', 2);
        $finding2 = new AuditResult('XSS_RAW_BLADE_ECHO', 'xss', AuditResult::SEVERITY_MEDIUM, 'XSS', 'D', 'resources/views/line2.blade.php', 2);
        $finding3 = new AuditResult('XSS_RAW_BLADE_ECHO', 'xss', AuditResult::SEVERITY_MEDIUM, 'XSS', 'D', 'resources/views/line3.blade.php', 3);

        $scanner = $this->createStubScanner('BladeScanner', [$finding1, $finding2, $finding3]);
        $engine  = new AuditEngine([], [$scanner]);
        $results = $engine->run($tempDir);

        $this->assertSame([], $results, 'All Blade findings should be ignored by various @waskita-ignore comment formats.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_ignores_static_js_attributes(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        $bladeFile = $tempDir . '/resources/views/test.blade.php';
        file_put_contents($bladeFile, '<button onclick="window.location.reload()">Reload</button>');

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertSame([], $results, 'Static onclick attribute should not be flagged as XSS.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_idor_scanner_skips_admin_controllers(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_idor_' . uniqid();
        mkdir($tempDir . '/app/Http/Controllers', 0777, true);

        $adminController = $tempDir . '/app/Http/Controllers/AdminBeritaController.php';
        file_put_contents($adminController, "<?php\nclass AdminBeritaController {\npublic function destroy(Berita \$berita) {}\n}\n");

        $scanner = new \Waskita\Security\Scanners\IdorScanner();
        $results = $scanner->scan($tempDir);

        $this->assertSame([], $results, 'Admin controller methods should not be flagged as IDOR.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_rate_limit_scanner_distinguishes_path_segments(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_ratelimit_' . uniqid();
        mkdir($tempDir . '/routes', 0777, true);

        // Rute pesan-masuk/balas tidak boleh disalahartikan sebagai login/masuk
        $routeFile = $tempDir . '/routes/web.php';
        file_put_contents($routeFile, "<?php\nRoute::post('/admin/pesan-masuk/1/balas', 'PesanController@balas');\n");

        $scanner = new \Waskita\Security\Scanners\RateLimitScanner();
        $results = $scanner->scan($tempDir);

        $this->assertSame([], $results, 'pesan-masuk route should not match masuk keyword.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_idor_scanner_accepts_form_request_with_authorization_logic(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_formreq_auth_' . uniqid();
        mkdir($tempDir . '/app/Http/Controllers', 0777, true);
        mkdir($tempDir . '/app/Http/Requests', 0777, true);

        $requestFile = $tempDir . '/app/Http/Requests/UpdateArtikelRequest.php';
        file_put_contents($requestFile, "<?php\nnamespace App\Http\Requests;\nclass UpdateArtikelRequest {\npublic function authorize(): bool {\nreturn \$this->user()->can('update', \$this->route('artikel'));\n}\n}\n");

        $controllerFile = $tempDir . '/app/Http/Controllers/ArtikelController.php';
        file_put_contents($controllerFile, "<?php\nnamespace App\Http\Controllers;\nuse App\Http\Requests\UpdateArtikelRequest;\nclass ArtikelController {\npublic function update(UpdateArtikelRequest \$request, Artikel \$artikel) {\n// update data\n}\n}\n");

        $scanner = new \Waskita\Security\Scanners\IdorScanner();
        $results = $scanner->scan($tempDir);

        $this->assertSame([], $results, 'Method with FormRequest containing authorize logic should not be flagged as IDOR.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_idor_scanner_flags_form_request_returning_true_without_checks(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_formreq_true_' . uniqid();
        mkdir($tempDir . '/app/Http/Controllers', 0777, true);
        mkdir($tempDir . '/app/Http/Requests', 0777, true);

        $requestFile = $tempDir . '/app/Http/Requests/UpdateBukuRequest.php';
        file_put_contents($requestFile, "<?php\nnamespace App\Http\Requests;\nclass UpdateBukuRequest {\npublic function authorize(): bool {\nreturn true;\n}\n}\n");

        $controllerFile = $tempDir . '/app/Http/Controllers/BukuController.php';
        file_put_contents($controllerFile, "<?php\nnamespace App\Http\Controllers;\nuse App\Http\Requests\UpdateBukuRequest;\nclass BukuController {\npublic function update(UpdateBukuRequest \$request, Buku \$buku) {\n\$buku->save();\n}\n}\n");

        $scanner = new \Waskita\Security\Scanners\IdorScanner();
        $results = $scanner->scan($tempDir);

        $this->assertCount(1, $results);
        $this->assertSame('IDOR_MISSING_AUTHORIZATION', $results[0]->ruleId);
        $this->assertStringContainsString('UpdateBukuRequest', $results[0]->description);
        $this->assertStringContainsString('mengembalikan nilai \'true\'', $results[0]->description);

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_idor_scanner_skips_when_authorize_resource_present(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_auth_res_' . uniqid();
        mkdir($tempDir . '/app/Http/Controllers', 0777, true);

        $controllerFile = $tempDir . '/app/Http/Controllers/ProdukController.php';
        file_put_contents($controllerFile, "<?php\nnamespace App\Http\Controllers;\nclass ProdukController {\npublic function __construct() {\n\$this->authorizeResource(Produk::class, 'produk');\n}\npublic function edit(Produk \$produk) {}\npublic function update(Request \$request, Produk \$produk) {}\npublic function destroy(Produk \$produk) {}\n}\n");

        $scanner = new \Waskita\Security\Scanners\IdorScanner();
        $results = $scanner->scan($tempDir);

        $this->assertSame([], $results, 'Controller with $this->authorizeResource() should not flag resource methods as IDOR.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_skips_accessor_sanitized_echo(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_acc_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);
        mkdir($tempDir . '/app/Models', 0777, true);

        $bladeFile = $tempDir . '/resources/views/test.blade.php';
        file_put_contents($bladeFile, '<div>{!! $item->safe_content !!}</div><div>{!! $berita->konten_aman !!}</div>');

        $modelFile = $tempDir . '/app/Models/Item.php';
        file_put_contents($modelFile, <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    public function getSafeContentAttribute(): string
    {
        return clean($this->attributes['content']);
    }
}
PHP
        );

        $beritaModel = $tempDir . '/app/Models/Berita.php';
        file_put_contents($beritaModel, <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Berita extends Model
{
    public function getKontenAmanAttribute()
    {
        return clean($this->attributes['konten']);
    }
}
PHP
        );

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertSame([], $results, 'Accessor with sanitization should not be flagged as XSS.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_supports_flat_model_directory(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_flat_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);
        mkdir($tempDir . '/app', 0777, true);

        $bladeFile = $tempDir . '/resources/views/test.blade.php';
        file_put_contents($bladeFile, '<div>{!! $article->safe_html !!}</div>');

        $modelFile = $tempDir . '/app/Article.php';
        file_put_contents($modelFile, <<<'PHP'
<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Article extends Model
{
    public function getSafeHtmlAttribute()
    {
        return clean($this->attributes['html']);
    }
}
PHP
        );

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertSame([], $results, 'Flat model accessor with sanitization should not be flagged.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_flags_accessor_without_sanitization(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_raw_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);
        mkdir($tempDir . '/app/Models', 0777, true);

        $bladeFile = $tempDir . '/resources/views/test.blade.php';
        file_put_contents($bladeFile, '<div>{!! $item->raw_content !!}</div>');

        $modelFile = $tempDir . '/app/Models/Item.php';
        file_put_contents($modelFile, <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Item extends Model
{
    public function getRawContentAttribute(): string
    {
        return $this->attributes['content'];
    }
}
PHP
        );

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertCount(1, $results);
        $this->assertSame('XSS_RAW_BLADE_ECHO', $results[0]->ruleId);

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_no_duplicate_csp_finding(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_csp_' . uniqid();
        mkdir($tempDir . '/resources/views/layouts', 0777, true);

        $layoutFile = $tempDir . '/resources/views/layouts/app.blade.php';
        file_put_contents($layoutFile, '<!DOCTYPE html><html><head><title>App</title></head><body><h1>Hello</h1></body></html>');

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $cspFindings = array_filter($results, fn ($r) => $r->ruleId === 'XSS_MISSING_CSP_META');
        $this->assertEmpty($cspFindings, 'XssScanner should not produce XSS_MISSING_CSP_META findings.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_skips_safe_callables_and_svg_helpers(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_safe_callables_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        $bladeFile = $tempDir . '/resources/views/icons.blade.php';
        file_put_contents($bladeFile, <<<'BLADE'
<div>
    {!! \App\Support\Icons::get('store') !!}
    {!! Icons::get('cart') !!}
    {!! svg('icon-user') !!}
    {!! heroicon('outline-check') !!}
    {!! icon('star') !!}
</div>
BLADE
        );

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertEmpty($results, 'XssScanner should not flag safe icon/svg helper calls as XSS.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_skips_static_literal_echo(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_static_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        $bladeFile = $tempDir . '/resources/views/static.blade.php';
        file_put_contents($bladeFile, <<<'BLADE'
<div>
    {!! '<span>Text Statis</span>' !!}
    {!! "<b>Bold Statis</b>" !!}
    {!! 12345 !!}
</div>
BLADE
        );

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertEmpty($results, 'XssScanner should not flag static literal echos without variables.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_skips_htmlable_and_htmlstring(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_htmlstring_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        $bladeFile = $tempDir . '/resources/views/htmlable.blade.php';
        file_put_contents($bladeFile, <<<'BLADE'
<div>
    {!! new \Illuminate\Support\HtmlString('<p>Hello</p>') !!}
    {!! new HtmlString('<b>Bold</b>') !!}
    {!! $table->toHtml() !!}
</div>
BLADE
        );

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertEmpty($results, 'XssScanner should recognize HtmlString and ->toHtml() as safe.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_skips_safe_numeric_formatting(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_format_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        $bladeFile = $tempDir . '/resources/views/format.blade.php';
        file_put_contents($bladeFile, <<<'BLADE'
<div>
    {!! number_format($price, 0, ',', '.') !!}
    {!! intval($qty) !!}
    {!! count($items) !!}
    {!! date('Y-m-d') !!}
</div>
BLADE
        );

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertEmpty($results, 'XssScanner should not flag safe formatting helpers.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_honors_custom_config_safe_callables_and_patterns(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_custom_config_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        $bladeFile = $tempDir . '/resources/views/custom.blade.php';
        file_put_contents($bladeFile, <<<'BLADE'
<div>
    {!! CustomRenderer::renderSvg('home') !!}
    {!! render_badge('active') !!}
</div>
BLADE
        );

        $config = [
            'xss' => [
                'safe_callables' => ['CustomRenderer::renderSvg'],
                'safe_patterns' => ['/render_badge\([^\)]+\)/'],
            ],
        ];

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir, $config);

        $this->assertEmpty($results, 'XssScanner should honor custom safe_callables and safe_patterns from config.');

        $this->deleteDirectoryRecursively($tempDir);
    }

    public function test_xss_scanner_still_flags_unsafe_dynamic_variables(): void
    {
        $tempDir = sys_get_temp_dir() . '/waskita_xss_unsafe_' . uniqid();
        mkdir($tempDir . '/resources/views', 0777, true);

        $bladeFile = $tempDir . '/resources/views/unsafe.blade.php';
        file_put_contents($bladeFile, '<div>{!! $user->bio !!}</div>');

        $scanner = new \Waskita\Security\Scanners\XssScanner();
        $results = $scanner->scan($tempDir);

        $this->assertCount(1, $results);
        $this->assertSame('XSS_RAW_BLADE_ECHO', $results[0]->ruleId);

        $this->deleteDirectoryRecursively($tempDir);
    }

    // ─────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────

    private function deleteDirectoryRecursively(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir) ?: [], ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->deleteDirectoryRecursively($path) : @unlink($path);
        }
        @rmdir($dir);
    }

    /**
     * Create a stub scanner that returns pre-configured results.
     *
     * @param  string          $name
     * @param  AuditResult[]   $results
     * @return ScannerInterface
     */
    private function createStubScanner(string $name, array $results): ScannerInterface
    {
        return new class($name, $results) implements ScannerInterface {
            /** @param AuditResult[] $results */
            public function __construct(
                private readonly string $name,
                private readonly array $results,
            ) {}

            public function getName(): string
            {
                return $this->name;
            }

            public function getDescription(): string
            {
                return "Stub scanner: {$this->name}";
            }

            public function scan(string $basePath, array $config = []): array
            {
                return $this->results;
            }
        };
    }
}
