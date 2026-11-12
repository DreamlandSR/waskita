<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Waskita\Security\Core\AstAnalyzer;

class AstAnalyzerTest extends TestCase
{
    private AstAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new AstAnalyzer();
    }

    public function test_parse_code_valid_and_invalid(): void
    {
        $stmts = $this->analyzer->parseCode('<?php echo "Hello";');
        $this->assertIsArray($stmts);
        $this->assertNotEmpty($stmts);

        // Invalid code returns null, does not throw
        $invalidStmts = $this->analyzer->parseCode('<?php function (((( {');
        $this->assertNull($invalidStmts);
    }

    public function test_extract_class_info(): void
    {
        $code = <<<'PHP'
<?php
namespace App\Services;

class PaymentService extends BaseService implements PaymentContract
{
    private string $apiKey;
    protected $timeout = 30;

    public function charge($amount)
    {
        return true;
    }
}
PHP;
        $stmts = $this->analyzer->parseCode($code);
        $this->assertNotNull($stmts);

        $classes = $this->analyzer->extractClassInfo($stmts);
        $this->assertCount(1, $classes);

        $cls = $classes[0];
        $this->assertSame('PaymentService', $cls['className']);
        $this->assertSame('App\Services', $cls['namespace']);
        $this->assertSame('BaseService', $cls['extends']);
        $this->assertContains('PaymentContract', $cls['implements']);
        $this->assertCount(2, $cls['properties']);
        $this->assertCount(1, $cls['methods']);
    }

    public function test_find_method_calls_and_static_calls(): void
    {
        $code = <<<'PHP'
<?php
$query->whereRaw("id = $id")->first();
$query->orderBy($request->sort);
DB::raw("SELECT * FROM users WHERE status = 1");
PHP;
        $stmts = $this->analyzer->parseCode($code);
        $this->assertNotNull($stmts);

        $whereRawCalls = $this->analyzer->findMethodCalls($stmts, 'whereRaw');
        $this->assertCount(1, $whereRawCalls);

        $orderByCalls = $this->analyzer->findMethodCalls($stmts, 'orderBy');
        $this->assertCount(1, $orderByCalls);

        $dbRawCalls = $this->analyzer->findStaticCalls($stmts, 'DB', 'raw');
        $this->assertCount(1, $dbRawCalls);
    }

    public function test_expression_analysis(): void
    {
        $code = <<<'PHP'
<?php
$a = "status = " . $status;
$b = "status = 1";
$c = "SELECT * FROM users WHERE id = {$id}";
$d = $request->input('name');
$e = clean($request->name);
PHP;
        $stmts = $this->analyzer->parseCode($code);
        $this->assertNotNull($stmts);

        $assignments = [];
        foreach ($stmts as $stmt) {
            if ($stmt instanceof \PhpParser\Node\Stmt\Expression &&
                $stmt->expr instanceof \PhpParser\Node\Expr\Assign &&
                $stmt->expr->var instanceof \PhpParser\Node\Expr\Variable) {
                $assignments[(string) $stmt->expr->var->name] = $stmt->expr->expr;
            }
        }

        $this->assertTrue($this->analyzer->isStringConcatenation($assignments['a']));
        $this->assertFalse($this->analyzer->isStringConcatenation($assignments['b']));

        $this->assertTrue($this->analyzer->isStringInterpolation($assignments['c']));
        $this->assertFalse($this->analyzer->isStringInterpolation($assignments['b']));

        $this->assertTrue($this->analyzer->containsUserInput($assignments['d']));
        $this->assertTrue($this->analyzer->isSanitized($assignments['e']));
    }

    public function test_find_return_statements(): void
    {
        $code = <<<'PHP'
<?php
function test($x) {
    if ($x > 0) {
        return true;
    }
    return false;
}
PHP;
        $stmts = $this->analyzer->parseCode($code);
        $this->assertNotNull($stmts);

        $returns = $this->analyzer->findReturnStatements($stmts);
        $this->assertCount(2, $returns);
    }
}
