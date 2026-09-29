<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Console\Commands;

use Ganadev\Shield\Laravel\Models\SecurityEvent;
use Ganadev\Shield\Laravel\Models\SecurityIpBan;
use Illuminate\Console\Command;

final class ShieldPruneCommand extends Command
{
    protected $signature = 'shield:prune {--days= : Prune security events older than N days (default dari config logging.retention_days)}';

    protected $description = 'Prune expired security events and clear expired bans.';

    public function handle(): int
    {
        $days = (int) ($this->option('days') ?: config('shield.logging.retention_days', 30));
        $cutoff = now()->subDays($days);

        $deletedEvents = SecurityEvent::query()
            ->where('created_at', '<', $cutoff)
            ->delete();

        // Hapus ban yang sudah rilis/kedaluwarsa. Pakai grouping agar
        // kondisi orWhere tidak membatalkan batasan status/expires_at.
        $deletedBans = SecurityIpBan::query()
            ->where(function ($query) {
                $query->where('status', 'released')
                    ->where('expires_at', '<', now());
            })
            ->orWhere('status', 'expired')
            ->delete();

        $this->info("Pruned {$deletedEvents} events older than {$days} days and {$deletedBans} stale bans.");

        return self::SUCCESS;
    }
}
