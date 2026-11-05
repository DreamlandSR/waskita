<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Unit;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Core\BaselineManager;
use PHPUnit\Framework\TestCase;

class BaselineTest extends TestCase
{
    private string $tempBaselinePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempBaselinePath = sys_get_temp_dir() . '/waskita_test_baseline_' . uniqid() . '.json';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempBaselinePath)) {
            @unlink($this->tempBaselinePath);
        }
        parent::tearDown();
    }

    public function test_baseline_manager_generates_consistent_signature(): void
    {
        $manager = new BaselineManager();

        $finding1 = new AuditResult(
            ruleId: 'XSS_RAW_BLADE_ECHO',
            category: 'xss',
            severity: AuditResult::SEVERITY_MEDIUM,
            title: 'Raw Blade Echo',
            description: 'Unescaped echo',
            file: 'resources/views/layouts/admin.blade.php',
            line: 442,
            codeSnippet: '<strong>{!! $title !!}</strong>'
        );

        // Finding dengan file format backslash (Windows) dan whitespace snippet berbeda
        $finding2 = new AuditResult(
            ruleId: 'XSS_RAW_BLADE_ECHO',
            category: 'xss',
            severity: AuditResult::SEVERITY_MEDIUM,
            title: 'Raw Blade Echo',
            description: 'Unescaped echo',
            file: 'resources\\views\\layouts\\admin.blade.php',
            line: 500, // Baris bergeser
            codeSnippet: '<strong>{!! $title !!}</strong>'
        );

        $sig1 = $manager->generateSignature($finding1);
        $sig2 = $manager->generateSignature($finding2);

        $this->assertSame($sig1, $sig2, 'Signature harus konsisten meskipun separator path atau baris bergeser.');
    }

    public function test_baseline_manager_saves_and_loads_valid_json(): void
    {
        $manager = new BaselineManager();

        $findings = [
            new AuditResult(
                ruleId: 'RATE_LIMIT_SENSITIVE_ENDPOINT',
                category: 'rate_limiting',
                severity: AuditResult::SEVERITY_HIGH,
                title: 'Missing Rate Limiting',
                description: 'Unthrottled endpoint',
                file: 'routes/web.php',
                line: 25,
                codeSnippet: "Route::post('/masuk', 'SesiController@masuk')"
            ),
        ];

        $count = $manager->saveBaseline($findings, $this->tempBaselinePath);
        $this->assertSame(1, $count);
        $this->assertFileExists($this->tempBaselinePath);

        $loaded = $manager->loadBaseline($this->tempBaselinePath);
        $this->assertNotNull($loaded);
        $this->assertSame(1, $loaded['total_findings']);
        $this->assertSame('RATE_LIMIT_SENSITIVE_ENDPOINT', $loaded['findings'][0]['rule_id']);
    }

    public function test_baseline_manager_filters_existing_findings_and_keeps_new_ones(): void
    {
        $manager = new BaselineManager();

        $oldFinding = new AuditResult(
            ruleId: 'XSS_RAW_BLADE_ECHO',
            category: 'xss',
            severity: AuditResult::SEVERITY_MEDIUM,
            title: 'Legacy XSS',
            description: 'Existing finding',
            file: 'resources/views/old.blade.php',
            line: 10,
            codeSnippet: '{!! $old !!}'
        );

        $newFinding = new AuditResult(
            ruleId: 'SQLI_RAW_QUERY',
            category: 'sqli',
            severity: AuditResult::SEVERITY_CRITICAL,
            title: 'New SQL Injection',
            description: 'Freshly introduced bug',
            file: 'app/Http/Controllers/NewController.php',
            line: 20,
            codeSnippet: 'DB::select("SELECT * FROM users WHERE id = " . $id)'
        );

        // Simpan hanya oldFinding ke dalam baseline
        $manager->saveBaseline([$oldFinding], $this->tempBaselinePath);

        // Jalankan filter terhadap kedua temuan
        $filterResult = $manager->filter([$oldFinding, $newFinding], $this->tempBaselinePath);

        $this->assertCount(1, $filterResult['suppressed'], 'Temuan lama harus disembunyikan oleh baseline.');
        $this->assertSame('XSS_RAW_BLADE_ECHO', $filterResult['suppressed'][0]->ruleId);

        $this->assertCount(1, $filterResult['active'], 'Temuan baru harus tetap aktif dilaporkan.');
        $this->assertSame('SQLI_RAW_QUERY', $filterResult['active'][0]->ruleId);
    }
}
