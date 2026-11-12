<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\XssScanner;

class XssGoldenTest extends GoldenTestCase
{
    private XssScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new XssScanner();
    }

    public function test_flags_raw_user_input_in_blade(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! $request->name !!}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'XSS_UNESCAPED_USER_INPUT', AuditResult::SEVERITY_CRITICAL);
    }

    public function test_passes_static_icon_helper(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! Icons::get(\'store\') !!}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_passes_html_string_constructor(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! new HtmlString(\'<p>ok</p>\') !!}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_passes_escaped_blade_echo(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{{ $user->name }}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_stored_xss_variable(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! $user->bio !!}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'XSS_RAW_BLADE_ECHO', AuditResult::SEVERITY_MEDIUM);
    }

    public function test_passes_sanitized_purifier(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! Purifier::clean($content) !!}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_passes_e_helper(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! e($user->name) !!}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_passes_number_format(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! number_format($price, 0, \',\', \'.\') !!}</div>');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_javascript_href(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<a href="javascript:{{ $action }}">Click</a>');

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'XSS_JAVASCRIPT_HREF', AuditResult::SEVERITY_HIGH);
    }

    public function test_flags_onclick_dynamic(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<button onclick="{{ $handler }}">Go</button>');

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'XSS_DANGEROUS_JS_ATTRIBUTE', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_onclick_static(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<button onclick="window.location.reload()">Reload</button>');

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_passes_accessor_with_sanitization(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! $item->safe_content !!}</div>');

        $modelContent = <<<'PHP'
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
PHP;
        $this->createFixtureFile($dir, 'app/Models/Item.php', $modelContent);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_accessor_without_sanitization(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '<div>{!! $item->raw_content !!}</div>');

        $modelContent = <<<'PHP'
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
PHP;
        $this->createFixtureFile($dir, 'app/Models/Item.php', $modelContent);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'XSS_RAW_BLADE_ECHO', AuditResult::SEVERITY_MEDIUM);
    }

    public function test_passes_custom_safe_callable_from_config(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'resources/views/test.blade.php', '{!! MyRenderer::widget(\'sidebar\') !!}');

        $config = [
            'xss' => [
                'safe_callables' => ['MyRenderer::widget'],
            ],
        ];

        $results = $this->scanner->scan($dir, $config);

        $this->assertMustPass($results);
    }
}
