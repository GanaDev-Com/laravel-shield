<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Console\Commands;

use Ganadev\Shield\Laravel\Models\SecurityEvent;
use Illuminate\Console\Command;

final class ShieldReportCommand extends Command
{
    protected $signature = 'shield:report {--host=}';

    protected $description = 'Print a security event summary report.';

    public function handle(): int
    {
        $query = SecurityEvent::query();
        if ($host = $this->option('host')) {
            $query->where('host', $host);
        }

        $total = (clone $query)->count();
        $blocked = (clone $query)->where('decision', 'BLOCK_REQUEST')->count();
        $offenders = (clone $query)->distinct('ip_address')->count('ip_address');

        $this->newLine();
        $this->info('Ganadev Shield Report');
        $this->newLine();
        $this->table(
            ['Metric', 'Value'],
            [
                ['Total events', $total],
                ['Blocked requests', $blocked],
                ['Unique offenders', $offenders],
            ],
        );

        $topRules = (clone $query)
            ->whereNotNull('rule_id')
            ->selectRaw('rule_id, count(*) as total')
            ->groupBy('rule_id')
            ->orderByDesc('total')
            ->limit(10)
            ->toBase()
            ->get();

        if ($topRules->isNotEmpty()) {
            $this->newLine();
            $this->info('Top matched rules');
            $this->table(['Rule', 'Count'], $topRules->map(fn ($row) => [$row->rule_id, $row->total])->all());
        }

        return self::SUCCESS;
    }
}
