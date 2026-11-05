<?php

declare(strict_types=1);

namespace Waskita\Security\Core;

use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ParseException;

/**
 * RuleLoader - Memuat rule YAML dari direktori default dan custom.
 *
 * Rules didefinisikan dalam file .yaml/.yml di bawah rules/default/
 * dan bisa di-override atau ditambah dari path custom.
 */
class RuleLoader
{
    /** @var array<string, array<string, mixed>> Cache rules yang sudah dimuat */
    private array $rules = [];

    /**
     * Muat semua rules dari direktori default package.
     *
     * @param string $packagePath Root path package waskita/agent
     * @return array<string, array<string, mixed>>
     */
    public function loadDefaultRules(string $packagePath): array
    {
        $defaultDir = rtrim($packagePath, '/') . '/rules/default';

        return $this->loadFromDirectory($defaultDir);
    }

    /**
     * Muat rules dari direktori custom (misal project-level rules).
     *
     * @param string $directory Path ke direktori berisi file YAML
     * @return array<string, array<string, mixed>>
     */
    public function loadFromDirectory(string $directory): array
    {
        if (! is_dir($directory)) {
            return [];
        }

        $files = glob($directory . '/*.{yaml,yml}', GLOB_BRACE);

        if ($files === false) {
            return [];
        }

        foreach ($files as $file) {
            $this->loadFile($file);
        }

        return $this->rules;
    }

    /**
     * Muat satu file YAML rule.
     *
     * @param string $filePath Path ke file YAML
     * @return array<string, mixed>|null
     */
    public function loadFile(string $filePath): ?array
    {
        if (! file_exists($filePath) || ! is_readable($filePath)) {
            return null;
        }

        try {
            $content = Yaml::parseFile($filePath);

            if (! is_array($content)) {
                return null;
            }

            // Jika file berisi multiple rules (array of rules)
            if (isset($content[0])) {
                foreach ($content as $rule) {
                    if (is_array($rule) && isset($rule['id'])) {
                        $this->rules[$rule['id']] = $rule;
                    }
                }
            }
            // Single rule
            elseif (isset($content['id'])) {
                $this->rules[$content['id']] = $content;
            }
            // Keyed rules (id => rule data)
            else {
                foreach ($content as $id => $rule) {
                    if (is_array($rule)) {
                        $rule['id'] = $rule['id'] ?? $id;
                        $this->rules[$rule['id']] = $rule;
                    }
                }
            }

            return $content;
        } catch (ParseException $e) {
            // Log error tapi jangan stop scanning
            error_log("Waskita: Failed to parse YAML rule file {$filePath}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Ambil semua rules yang sudah dimuat.
     *
     * @return array<string, array<string, mixed>>
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    /**
     * Ambil rule berdasarkan ID.
     *
     * @return array<string, mixed>|null
     */
    public function getRule(string $ruleId): ?array
    {
        return $this->rules[$ruleId] ?? null;
    }

    /**
     * Reset cache rules (untuk testing atau reload).
     */
    public function reset(): void
    {
        $this->rules = [];
    }
}
