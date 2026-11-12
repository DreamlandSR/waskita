<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\CsrfScanner;

class CsrfGoldenTest extends GoldenTestCase
{
    private CsrfScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new CsrfScanner();
    }

    public function test_flags_wildcard_csrf_except(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'bootstrap/app.php', <<<'PHP'
<?php

$app->withMiddleware(function ($middleware) {
    $middleware->validateCsrfTokens(except: ['*']);
});
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'CSRF_WILDCARD_EXCEPT', AuditResult::SEVERITY_CRITICAL);
    }

    public function test_passes_no_csrf_exception(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'bootstrap/app.php', <<<'PHP'
<?php

$app = Application::configure(basePath: dirname(__DIR__))->create();
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_sensitive_route_excluded(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'bootstrap/app.php', <<<'PHP'
<?php

$app->withMiddleware(function ($middleware) {
    $middleware->validateCsrfTokens(except: ['api/webhook', 'payment/callback']);
});
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'CSRF_SENSITIVE_ROUTE_EXCLUDED', AuditResult::SEVERITY_HIGH);
    }

    public function test_flags_form_without_csrf(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', <<<'HTML'
<form method="POST" action="/submit">
    <input type="text" name="data">
    <button type="submit">Submit</button>
</form>
HTML);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'CSRF_MISSING_TOKEN_IN_FORM', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_form_with_csrf(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', <<<'HTML'
<form method="POST" action="/submit">
    @csrf
    <input type="text" name="data">
    <button type="submit">Submit</button>
</form>
HTML);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }
}
