<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

use PhpParser\Modifiers;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard as PrettyPrinter;

/**
 * AstAnalyzer - Pembungkus nikic/php-parser v5 untuk analisis statis keamanan.
 *
 * Menyediakan metode reusable untuk parsing file PHP, ekstraksi informasi
 * kelas/method/properti, pencarian node AST, dan analisis ekspresi
 * yang digunakan oleh seluruh scanner Waskita.
 */
class AstAnalyzer
{
    private readonly Parser $parser;

    private readonly PrettyPrinter $printer;

    private readonly NodeFinder $nodeFinder;

    /**
     * @param Parser|null $parser Instance parser PHP (default: parser untuk versi terbaru yang didukung)
     */
    public function __construct(?Parser $parser = null)
    {
        $this->parser = $parser ?? (new ParserFactory())->createForNewestSupportedVersion();
        $this->printer = new PrettyPrinter();
        $this->nodeFinder = new NodeFinder();
    }

    // =========================================================================
    // Core Parsing
    // =========================================================================

    /**
     * Parse file PHP menjadi AST nodes.
     *
     * @param string $filePath Path absolut atau relatif ke file PHP
     * @return Node\Stmt[]|null Array statement nodes, atau null jika gagal
     */
    public function parseFile(string $filePath): ?array
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            return null;
        }

        $code = @file_get_contents($filePath);
        if ($code === false) {
            return null;
        }

        return $this->parseCode($code);
    }

    /**
     * Parse string kode PHP menjadi AST nodes.
     *
     * @param string $code Kode PHP lengkap (termasuk tag <?php)
     * @return Node\Stmt[]|null Array statement nodes, atau null jika gagal
     */
    public function parseCode(string $code): ?array
    {
        try {
            $stmts = $this->parser->parse($code);

            return $stmts ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    // =========================================================================
    // Class Analysis
    // =========================================================================

    /**
     * Ekstrak informasi seluruh kelas yang ditemukan dalam AST.
     *
     * Mendukung kelas di dalam namespace maupun tanpa namespace,
     * serta file dengan multiple class declarations.
     *
     * @param Node\Stmt[] $stmts Statement nodes hasil parsing
     * @return list<array{
     *     className: string,
     *     namespace: string,
     *     extends: ?string,
     *     implements: string[],
     *     traits: string[],
     *     properties: list<array{name: string, defaultValue: ?string, visibility: string, type: ?string, isStatic: bool, line: int}>,
     *     methods: list<array{name: string, params: list<array{name: string, type: ?string, default: ?string, byRef: bool, isVariadic: bool}>, returnType: ?string, body: Node\Stmt[], startLine: int, endLine: int, visibility: string, isStatic: bool}>
     * }>
     */
    public function extractClassInfo(array $stmts): array
    {
        $results = [];
        $currentNamespace = '';

        // Resolve namespace context first
        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Namespace_) {
                $ns = $stmt->name !== null ? $stmt->name->toString() : '';

                // Process classes inside this namespace block
                foreach ($this->findClassNodes($stmt->stmts) as $classNode) {
                    $results[] = $this->buildClassInfo($classNode, $ns);
                }
            } elseif ($stmt instanceof Stmt\Class_
                || $stmt instanceof Stmt\Interface_
                || $stmt instanceof Stmt\Trait_
                || $stmt instanceof Stmt\Enum_) {
                // Top-level class without namespace
                $results[] = $this->buildClassInfo($stmt, $currentNamespace);
            }
        }

        return $results;
    }

    /**
     * Ekstrak informasi seluruh method dari AST statements.
     *
     * Mencari method di semua level: top-level statements, di dalam kelas,
     * dan di dalam namespace blocks.
     *
     * @param Node\Stmt[] $stmts Statement nodes (bisa berupa stmts dari kelas atau file)
     * @return list<array{
     *     name: string,
     *     params: list<array{name: string, type: ?string, default: ?string, byRef: bool, isVariadic: bool}>,
     *     returnType: ?string,
     *     body: Node\Stmt[],
     *     startLine: int,
     *     endLine: int,
     *     visibility: string,
     *     isStatic: bool
     * }>
     */
    public function extractMethods(array $stmts): array
    {
        $methods = [];

        /** @var Stmt\ClassMethod[] $methodNodes */
        $methodNodes = $this->nodeFinder->findInstanceOf($stmts, Stmt\ClassMethod::class);

        foreach ($methodNodes as $method) {
            $methods[] = $this->buildMethodInfo($method);
        }

        return $methods;
    }

    /**
     * Ekstrak informasi seluruh properti dari AST statements.
     *
     * @param Node\Stmt[] $stmts Statement nodes (bisa berupa stmts dari kelas atau file)
     * @return list<array{
     *     name: string,
     *     defaultValue: ?string,
     *     visibility: string,
     *     type: ?string,
     *     isStatic: bool,
     *     line: int
     * }>
     */
    public function extractProperties(array $stmts): array
    {
        $properties = [];

        /** @var Stmt\Property[] $propNodes */
        $propNodes = $this->nodeFinder->findInstanceOf($stmts, Stmt\Property::class);

        foreach ($propNodes as $propNode) {
            $visibility = $this->resolveVisibility($propNode->flags);
            $type = $propNode->type !== null ? $this->prettyPrint($propNode->type) : null;
            $isStatic = $propNode->isStatic();

            foreach ($propNode->props as $prop) {
                $properties[] = [
                    'name' => $prop->name->toString(),
                    'defaultValue' => $prop->default !== null
                        ? $this->getExpressionString($prop->default)
                        : null,
                    'visibility' => $visibility,
                    'type' => $type,
                    'isStatic' => $isStatic,
                    'line' => $prop->getStartLine(),
                ];
            }
        }

        return $properties;
    }

    // =========================================================================
    // Method Body Analysis
    // =========================================================================

    /**
     * Temukan semua pemanggilan method instance dengan nama tertentu.
     *
     * Mencari pola $obj->methodName() dan $obj?->methodName()
     * (MethodCall dan NullsafeMethodCall).
     *
     * @param Node\Stmt[] $stmts Statement nodes untuk dicari
     * @param string $methodName Nama method yang dicari
     * @return list<array{node: Expr\MethodCall|Expr\NullsafeMethodCall, line: int, args: Node\Arg[]}>
     */
    public function findMethodCalls(array $stmts, string $methodName): array
    {
        $results = [];

        $nodes = $this->nodeFinder->find($stmts, function (Node $node) use ($methodName): bool {
            if (!$node instanceof Expr\MethodCall && !$node instanceof Expr\NullsafeMethodCall) {
                return false;
            }

            // Dynamic method names ($obj->$method()) — skip, can't match statically
            if (!$node->name instanceof Node\Identifier) {
                return false;
            }

            return strcasecmp($node->name->toString(), $methodName) === 0;
        });

        foreach ($nodes as $node) {
            /** @var Expr\MethodCall|Expr\NullsafeMethodCall $node */
            $results[] = [
                'node' => $node,
                'line' => $node->getStartLine(),
                'args' => $node->args,
            ];
        }

        return $results;
    }

    /**
     * Temukan semua pemanggilan method statis ClassName::methodName().
     *
     * @param Node\Stmt[] $stmts Statement nodes untuk dicari
     * @param string $className Nama kelas yang dicari (e.g. 'DB', 'Gate', 'Auth')
     * @param string $methodName Nama method yang dicari (e.g. 'raw', 'authorize')
     * @return list<array{node: Expr\StaticCall, line: int, args: Node\Arg[], class: string, method: string}>
     */
    public function findStaticCalls(array $stmts, string $className, string $methodName): array
    {
        $results = [];

        $nodes = $this->nodeFinder->find($stmts, function (Node $node) use ($className, $methodName): bool {
            if (!$node instanceof Expr\StaticCall) {
                return false;
            }

            // Class name must be a resolvable Name, not a dynamic expression
            if (!$node->class instanceof Node\Name) {
                return false;
            }

            // Method name must be a static Identifier
            if (!$node->name instanceof Node\Identifier) {
                return false;
            }

            $classMatch = strcasecmp($node->class->getLast(), $className) === 0
                || strcasecmp($node->class->toString(), $className) === 0;

            $methodMatch = strcasecmp($node->name->toString(), $methodName) === 0;

            return $classMatch && $methodMatch;
        });

        foreach ($nodes as $node) {
            /** @var Expr\StaticCall $node */
            $results[] = [
                'node' => $node,
                'line' => $node->getStartLine(),
                'args' => $node->args,
                'class' => $node->class->toString(),
                'method' => $node->name->toString(),
            ];
        }

        return $results;
    }

    /**
     * Temukan semua assignment ke variabel tertentu ($varName = ...).
     *
     * @param Node\Stmt[] $stmts Statement nodes untuk dicari
     * @param string $varName Nama variabel tanpa $ (e.g. 'query', 'input', 'data')
     * @return list<array{node: Expr\Assign, line: int, var: string, expr: Expr}>
     */
    public function findVariableAssignments(array $stmts, string $varName): array
    {
        $results = [];

        $nodes = $this->nodeFinder->find($stmts, function (Node $node) use ($varName): bool {
            if (!$node instanceof Expr\Assign) {
                return false;
            }

            if (!$node->var instanceof Expr\Variable) {
                return false;
            }

            // Variable name can be a string or an Expr (dynamic variable $$var)
            return is_string($node->var->name) && $node->var->name === $varName;
        });

        foreach ($nodes as $node) {
            /** @var Expr\Assign $node */
            $results[] = [
                'node' => $node,
                'line' => $node->getStartLine(),
                'var' => is_string($node->var->name) ? $node->var->name : $this->getExpressionString($node->var),
                'expr' => $node->expr,
            ];
        }

        return $results;
    }

    /**
     * Temukan semua return statements dalam AST nodes.
     *
     * @param Node\Stmt[] $stmts Statement nodes untuk dicari
     * @return list<array{node: Stmt\Return_, line: int, expr: ?Expr}>
     */
    public function findReturnStatements(array $stmts): array
    {
        $results = [];

        /** @var Stmt\Return_[] $nodes */
        $nodes = $this->nodeFinder->findInstanceOf($stmts, Stmt\Return_::class);

        foreach ($nodes as $node) {
            $results[] = [
                'node' => $node,
                'line' => $node->getStartLine(),
                'expr' => $node->expr,
            ];
        }

        return $results;
    }

    // =========================================================================
    // Expression Analysis
    // =========================================================================

    /**
     * Periksa apakah pohon ekspresi mengandung variabel ($var) di mana saja.
     *
     * @param Expr $expr Ekspresi AST yang diperiksa
     * @return bool True jika ditemukan variabel dalam ekspresi
     */
    public function containsVariable(Expr $expr): bool
    {
        if ($expr instanceof Expr\Variable) {
            return true;
        }

        // Use NodeFinder to search the entire expression subtree
        $found = $this->nodeFinder->findFirst([$expr], function (Node $node): bool {
            return $node instanceof Expr\Variable;
        });

        return $found !== null;
    }

    /**
     * Periksa apakah ekspresi mengandung pola user input (request/input tainted sources).
     *
     * Pengecekan dilakukan terhadap LaravelSecurityDictionary::USER_INPUT_SOURCES
     * pada representasi pretty-printed dari ekspresi AST.
     *
     * @param Expr $expr Ekspresi AST yang diperiksa
     * @return bool True jika ekspresi mengandung sumber input pengguna
     */
    public function containsUserInput(Expr $expr): bool
    {
        $code = $this->getExpressionString($expr);

        return LaravelSecurityDictionary::containsUserInput($code);
    }

    /**
     * Periksa apakah ekspresi dibungkus oleh fungsi sanitizer.
     *
     * Pengecekan dilakukan terhadap LaravelSecurityDictionary::XSS_SANITIZERS
     * pada representasi pretty-printed dari ekspresi AST.
     *
     * @param Expr $expr Ekspresi AST yang diperiksa
     * @return bool True jika ekspresi disanitasi oleh fungsi yang dikenal
     */
    public function isSanitized(Expr $expr): bool
    {
        $code = $this->getExpressionString($expr);

        return LaravelSecurityDictionary::isSanitized($code);
    }

    /**
     * Periksa apakah ekspresi merupakan konkatenasi string dengan variabel.
     *
     * Mendeteksi pola seperti: "SELECT * FROM " . $table atau $prefix . $query
     *
     * @param Expr $expr Ekspresi AST yang diperiksa
     * @return bool True jika ekspresi adalah konkatenasi string yang mengandung variabel
     */
    public function isStringConcatenation(Expr $expr): bool
    {
        if (!$expr instanceof Expr\BinaryOp\Concat) {
            return false;
        }

        return $this->containsVariable($expr);
    }

    /**
     * Periksa apakah ekspresi mengandung interpolasi variabel (string petik ganda).
     *
     * Mendeteksi pola seperti: "SELECT * FROM $table" atau "Hello {$name}!"
     *
     * @param Expr $expr Ekspresi AST yang diperiksa
     * @return bool True jika ekspresi mengandung interpolasi variabel
     */
    public function isStringInterpolation(Expr $expr): bool
    {
        // InterpolatedString is the canonical v5 class; Encapsed is a deprecated alias
        if ($expr instanceof Node\Scalar\InterpolatedString) {
            return true;
        }

        // Fallback for legacy Encapsed alias
        if ($expr instanceof Node\Scalar\Encapsed) {
            return true;
        }

        // Also check nested: expression tree may contain interpolated strings
        $found = $this->nodeFinder->findFirst([$expr], function (Node $node): bool {
            return $node instanceof Node\Scalar\InterpolatedString
                || $node instanceof Node\Scalar\Encapsed;
        });

        return $found !== null;
    }

    // =========================================================================
    // Traversal Helpers
    // =========================================================================

    /**
     * Temukan semua node yang merupakan instance dari kelas tertentu.
     *
     * @template T of Node
     *
     * @param Node\Stmt[] $stmts Statement nodes untuk dicari
     * @param class-string<T> $nodeClass Nama kelas node (e.g. Expr\FuncCall::class)
     * @return T[] Array node yang cocok
     */
    public function findNodes(array $stmts, string $nodeClass): array
    {
        return $this->nodeFinder->findInstanceOf($stmts, $nodeClass);
    }

    /**
     * Temukan semua node yang memenuhi predicate callback.
     *
     * @param Node\Stmt[] $stmts Statement nodes untuk dicari
     * @param callable(Node): bool $predicate Fungsi filter: menerima Node, mengembalikan bool
     * @return Node[] Array node yang memenuhi predicate
     */
    public function findNodesMatching(array $stmts, callable $predicate): array
    {
        return $this->nodeFinder->find($stmts, $predicate);
    }

    /**
     * Dapatkan konteks (kelas dan method) yang membungkus node target.
     *
     * Berguna untuk mengetahui di method mana dan kelas mana suatu node berada.
     *
     * @param Node\Stmt[] $stmts Statement nodes root (seluruh AST file)
     * @param Node $targetNode Node yang ingin dicari konteksnya
     * @return array{class: ?string, method: ?string, namespace: ?string}|null Konteks, atau null jika tidak ditemukan
     */
    public function getNodeContext(array $stmts, Node $targetNode): ?array
    {
        $context = [
            'namespace' => null,
            'class' => null,
            'method' => null,
        ];

        $targetLine = $targetNode->getStartLine();
        $found = false;

        $visitor = new class ($targetNode, $context, $found) extends NodeVisitorAbstract {
            private ?string $currentNamespace = null;

            private ?string $currentClass = null;

            private ?string $currentMethod = null;

            /**
             * @param array{namespace: ?string, class: ?string, method: ?string} $context
             */
            public function __construct(
                private readonly Node $target,
                private array &$context,
                private bool &$found,
            ) {}

            public function enterNode(Node $node): ?int
            {
                if ($this->found) {
                    return NodeTraverser::DONT_TRAVERSE_CHILDREN;
                }

                if ($node instanceof Stmt\Namespace_) {
                    $this->currentNamespace = $node->name?->toString();
                }

                if ($node instanceof Stmt\Class_
                    || $node instanceof Stmt\Interface_
                    || $node instanceof Stmt\Trait_
                    || $node instanceof Stmt\Enum_) {
                    $this->currentClass = $node->name?->toString();
                }

                if ($node instanceof Stmt\ClassMethod) {
                    $this->currentMethod = $node->name->toString();
                }

                if ($node === $this->target) {
                    $this->context = [
                        'namespace' => $this->currentNamespace,
                        'class' => $this->currentClass,
                        'method' => $this->currentMethod,
                    ];
                    $this->found = true;

                    return NodeTraverser::DONT_TRAVERSE_CHILDREN;
                }

                return null;
            }

            public function leaveNode(Node $node): void
            {
                if ($node instanceof Stmt\ClassMethod) {
                    $this->currentMethod = null;
                }

                if ($node instanceof Stmt\Class_
                    || $node instanceof Stmt\Interface_
                    || $node instanceof Stmt\Trait_
                    || $node instanceof Stmt\Enum_) {
                    $this->currentClass = null;
                }
            }
        };

        $traverser = new NodeTraverser($visitor);
        $traverser->traverse($stmts);

        return $found ? $context : null;
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /**
     * Konversi node AST kembali menjadi kode PHP.
     *
     * @param Node $node Node AST yang akan di-render
     * @return string Representasi kode PHP dari node
     */
    public function prettyPrint(Node $node): string
    {
        try {
            return $this->printer->prettyPrint([$node]);
        } catch (\Throwable) {
            // Fallback: coba print sebagai ekspresi tunggal
            try {
                return $this->printer->prettyPrintExpr($node);
            } catch (\Throwable) {
                return '';
            }
        }
    }

    /**
     * Representasi string terbaik (best-effort) dari ekspresi AST.
     *
     * Untuk variabel mengembalikan "$name", untuk literal mengembalikan nilainya,
     * untuk ekspresi kompleks menggunakan pretty printer.
     *
     * @param Expr $expr Ekspresi AST
     * @return string Representasi string dari ekspresi
     */
    public function getExpressionString(Expr $expr): string
    {
        try {
            return $this->printer->prettyPrintExpr($expr);
        } catch (\Throwable) {
            return '';
        }
    }

    // =========================================================================
    // Private Helpers
    // =========================================================================

    /**
     * Temukan semua class-like nodes (Class, Interface, Trait, Enum) di statements.
     *
     * @param Node\Stmt[] $stmts
     * @return list<Stmt\ClassLike>
     */
    private function findClassNodes(array $stmts): array
    {
        $classes = [];

        foreach ($stmts as $stmt) {
            if ($stmt instanceof Stmt\Class_
                || $stmt instanceof Stmt\Interface_
                || $stmt instanceof Stmt\Trait_
                || $stmt instanceof Stmt\Enum_) {
                $classes[] = $stmt;
            }
        }

        return $classes;
    }

    /**
     * Bangun array informasi kelas dari node ClassLike.
     *
     * @param Stmt\ClassLike $classNode Node kelas
     * @param string $namespace Namespace saat ini
     * @return array{
     *     className: string,
     *     namespace: string,
     *     extends: ?string,
     *     implements: string[],
     *     traits: string[],
     *     properties: list<array{name: string, defaultValue: ?string, visibility: string, type: ?string, isStatic: bool, line: int}>,
     *     methods: list<array{name: string, params: list<array{name: string, type: ?string, default: ?string, byRef: bool, isVariadic: bool}>, returnType: ?string, body: Node\Stmt[], startLine: int, endLine: int, visibility: string, isStatic: bool}>
     * }
     */
    private function buildClassInfo(Stmt\ClassLike $classNode, string $namespace): array
    {
        $extends = null;
        if ($classNode instanceof Stmt\Class_ && $classNode->extends !== null) {
            $extends = $classNode->extends->toString();
        } elseif ($classNode instanceof Stmt\Enum_ && $classNode->scalarType !== null) {
            // Enums don't extend, but may have a scalar type — skip for extends
        } elseif ($classNode instanceof Stmt\Interface_) {
            // Interfaces can extend multiple interfaces
            $extends = !empty($classNode->extends) ? $classNode->extends[0]->toString() : null;
        }

        $implements = [];
        if ($classNode instanceof Stmt\Class_) {
            $implements = array_map(
                static fn(Node\Name $name): string => $name->toString(),
                $classNode->implements
            );
        } elseif ($classNode instanceof Stmt\Enum_) {
            $implements = array_map(
                static fn(Node\Name $name): string => $name->toString(),
                $classNode->implements
            );
        }

        // Extract traits
        $traits = [];
        foreach ($classNode->getTraitUses() as $traitUse) {
            foreach ($traitUse->traits as $traitName) {
                $traits[] = $traitName->toString();
            }
        }

        return [
            'className' => $classNode->name?->toString() ?? '(anonymous)',
            'namespace' => $namespace,
            'extends' => $extends,
            'implements' => $implements,
            'traits' => $traits,
            'properties' => $this->extractProperties($classNode->stmts),
            'methods' => $this->extractMethods($classNode->stmts),
        ];
    }

    /**
     * Bangun array informasi method dari node ClassMethod.
     *
     * @param Stmt\ClassMethod $method Node method
     * @return array{
     *     name: string,
     *     params: list<array{name: string, type: ?string, default: ?string, byRef: bool, isVariadic: bool}>,
     *     returnType: ?string,
     *     body: Node\Stmt[],
     *     startLine: int,
     *     endLine: int,
     *     visibility: string,
     *     isStatic: bool
     * }
     */
    private function buildMethodInfo(Stmt\ClassMethod $method): array
    {
        $params = [];
        foreach ($method->params as $param) {
            $params[] = [
                'name' => $param->var instanceof Expr\Variable && is_string($param->var->name)
                    ? $param->var->name
                    : $this->getExpressionString($param->var),
                'type' => $param->type !== null ? $this->prettyPrint($param->type) : null,
                'default' => $param->default !== null ? $this->getExpressionString($param->default) : null,
                'byRef' => $param->byRef,
                'isVariadic' => $param->variadic,
            ];
        }

        return [
            'name' => $method->name->toString(),
            'params' => $params,
            'returnType' => $method->returnType !== null
                ? $this->prettyPrint($method->returnType)
                : null,
            'body' => $method->stmts ?? [],
            'startLine' => $method->getStartLine(),
            'endLine' => $method->getEndLine(),
            'visibility' => $this->resolveVisibility($method->flags),
            'isStatic' => $method->isStatic(),
        ];
    }

    /**
     * Tentukan string visibility dari flags modifier.
     *
     * @param int $flags Bit mask flags dari Modifiers
     * @return string 'public', 'protected', atau 'private'
     */
    private function resolveVisibility(int $flags): string
    {
        if (($flags & Modifiers::PRIVATE) !== 0) {
            return 'private';
        }

        if (($flags & Modifiers::PROTECTED) !== 0) {
            return 'protected';
        }

        return 'public';
    }
}
