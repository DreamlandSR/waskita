<?php

declare(strict_types=1);

namespace Waskita\Security\Tests\Golden;

use Waskita\Security\Core\AuditResult;
use Waskita\Security\Scanners\IdorScanner;

class IdorGoldenTest extends GoldenTestCase
{
    private IdorScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new IdorScanner();
    }

    public function test_flags_no_auth_check_on_resource_action(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/PostController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function destroy(Post $post)
    {
        $post->delete();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'IDOR_MISSING_AUTHORIZATION', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_with_authorize_call(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/PostController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class PostController
{
    public function destroy(Post $post)
    {
        $this->authorize('delete', $post);
        $post->delete();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_passes_admin_controller_skip(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/AdminPostController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class AdminPostController
{
    public function destroy(Post $post)
    {
        $post->delete();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_passes_authorize_resource_in_constructor(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/ArticleController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class ArticleController
{
    public function __construct()
    {
        $this->authorizeResource(Article::class, 'article');
    }

    public function edit(Article $article)
    {
    }

    public function update(Request $request, Article $article)
    {
    }

    public function destroy(Article $article)
    {
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_form_request_returning_true(): void
    {
        $dir = $this->createFixtureDir();

        $this->createFixtureFile($dir, 'app/Http/Requests/UpdateItemRequest.php', <<<'PHP'
<?php

namespace App\Http\Requests;

class UpdateItemRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [];
    }
}
PHP);

        $this->createFixtureFile($dir, 'app/Http/Controllers/ItemController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\UpdateItemRequest;

class ItemController
{
    public function update(UpdateItemRequest $request, Item $item)
    {
        $item->save();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'IDOR_MISSING_AUTHORIZATION', AuditResult::SEVERITY_HIGH);
    }

    public function test_passes_form_request_with_policy(): void
    {
        $dir = $this->createFixtureDir();

        $this->createFixtureFile($dir, 'app/Http/Requests/UpdateItemRequest.php', <<<'PHP'
<?php

namespace App\Http\Requests;

class UpdateItemRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('update', $this->route('item'));
    }

    public function rules(): array
    {
        return [];
    }
}
PHP);

        $this->createFixtureFile($dir, 'app/Http/Controllers/ItemController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\UpdateItemRequest;

class ItemController
{
    public function update(UpdateItemRequest $request, Item $item)
    {
        $item->save();
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustPass($results);
    }

    public function test_flags_direct_find_without_scope(): void
    {
        $dir = $this->createFixtureDir();
        $this->createFixtureFile($dir, 'app/Http/Controllers/InvoiceController.php', <<<'PHP'
<?php

namespace App\Http\Controllers;

class InvoiceController
{
    public function print($id)
    {
        $invoice = Invoice::findOrFail($id);
        return view('invoices.print', compact('invoice'));
    }
}
PHP);

        $results = $this->scanner->scan($dir);

        $this->assertMustFlag($results, 'IDOR_MISSING_AUTHORIZATION', AuditResult::SEVERITY_HIGH);
    }
}
