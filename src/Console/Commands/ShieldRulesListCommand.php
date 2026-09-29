<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Console\Commands;

use Ganadev\Shield\Core\Rules\RuleRepository;
use Illuminate\Console\Command;

final class ShieldRulesListCommand extends Command
{
    protected $signature = 'shield:rules:list {--disabled : Show disabled rules too}';

    protected $description = 'List loaded threat rules and their version.';

    public function handle(RuleRepository $rules): int
    {
        $rows = [];
        foreach ($rules->all() as $rule) {
            if (! $rule->enabled && ! $this->option('disabled')) {
                continue;
            }

            $rows[] = [
                $rule->id,
                $rule->category,
                $rule->matcher->value,
                $rule->severity->value,
                $rule->score,
                $rule->immediateBan ? 'yes' : 'no',
                $rule->enabled ? 'enabled' : 'disabled',
            ];
        }

        $this->table(
            ['ID', 'Category', 'Matcher', 'Severity', 'Score', 'Immediate Ban', 'State'],
            $rows,
        );

        $this->info('Loaded '.count($rows).' rule(s).');

        return self::SUCCESS;
    }
}
