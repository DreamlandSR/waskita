<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\SecurityHeaderScanner;

class SecurityHeadersGoldenTest extends GoldenTestCase
{
    private SecurityHeaderScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new SecurityHeaderScanner();
    }

    public function test_flags_missing_headers_middleware(): void
    {
        $dir = $this->createFixtureDir();
        // Empty project — no middleware, no htaccess, no kernel, no composer.json
        // Create an empty placeholder so the directory is not entirely empty
        $this->createFixtureFile($dir, 'bootstrap/app.php', '<?php // empty');

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'SEC_HEADERS_MISSING_MIDDLEWARE', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_with_secure_headers_package(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'composer.json', '{"require": {"bepsvpt/secure-headers": "^7.0"}}');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_individual_missing_headers(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Middleware/SecurityHeaders.php', <<<'PHP'
<?php

namespace App\Http\Middleware;

class SecurityHeaders
{
    public function handle($request, $next)
    {
        $response = $next($request);
        $response->header('X-Frame-Options', 'DENY');
        $response->header('X-Content-Type-Options', 'nosniff');
        return $response;
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        // HSTS is missing, should be flagged
        $this->assertMustFlag($results, 'SEC_HEADER_HSTS_MISSING');

        // X-Frame-Options and X-Content-Type-Options are present, should NOT be flagged
        $this->assertMustNotFlag($results, 'SEC_HEADER_X_FRAME_OPTIONS_MISSING');
        $this->assertMustNotFlag($results, 'SEC_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING');
    }
}
