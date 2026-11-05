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

    // ─────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────

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
