<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\EnvironmentConfigScanner;

class EnvironmentConfigGoldenTest extends GoldenTestCase
{
    private EnvironmentConfigScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new EnvironmentConfigScanner();
    }

    public function test_flags_debug_true_in_production(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, '.env', <<<'ENV'
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:abc123def456ghi789jkl012mno345pq=
ENV);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'ENV_APP_DEBUG_PRODUCTION', AuditResult::SEVERITY_CRITICAL);
    }

    public function test_passes_debug_false_in_production(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, '.env', <<<'ENV'
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:abc123def456ghi789jkl012mno345pq=
ENV);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_empty_app_key(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, '.env', <<<'ENV'
APP_ENV=local
APP_DEBUG=true
APP_KEY=
ENV);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'ENV_APP_KEY_EMPTY', AuditResult::SEVERITY_CRITICAL);
    }

    public function test_flags_http_only_false_in_session_config(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'config/session.php', <<<'PHP'
<?php

return [
    'http_only' => false,
];
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'CONFIG_SESSION_HTTP_ONLY_FALSE', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_http_only_true_in_session_config(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'config/session.php', <<<'PHP'
<?php

return [
    'http_only' => true,
];
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_hardcoded_debug_true_in_app_config(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'config/app.php', <<<'PHP'
<?php

return [
    'debug' => true,
];
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'CONFIG_APP_DEBUG_HARDCODED', AuditResult::SEVERITY_HIGH);
    }
}
