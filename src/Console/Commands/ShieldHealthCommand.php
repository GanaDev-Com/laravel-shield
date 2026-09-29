<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\Request;

final class ShieldHealthCommand extends Command
{
    protected $signature = 'shield:health';

    protected $description = 'Cek kesehatan komponen Ganadev Shield.';

    public function handle(DatabaseManager $db, Repository $cache): int
    {
        $healthy = true;

        try {
            $db->getPdo();
            $dbStatus = 'ok';
        } catch (\Throwable $e) {
            $dbStatus = 'down ('.$e->getMessage().')';
            $healthy = false;
        }

        try {
            $cache->get('shield:health:probe');
            $cacheStatus = 'ok';
        } catch (\Throwable $e) {
            $cacheStatus = 'down ('.$e->getMessage().')';
            $healthy = false;
        }

        [$proxyStatus, $proxyWarning] = $this->proxyStatus();

        $this->table(
            ['Component', 'Status'],
            [
                ['Database', $dbStatus],
                ['Cache', $cacheStatus],
                ['Rule engine', 'ok'],
                ['Trusted proxy', $proxyStatus],
            ],
        );

        if ($proxyWarning !== null) {
            $this->newLine();
            $this->warn('Peringatan trusted proxy: '.$proxyWarning);
            $this->line('Konfigurasikan trusted proxies di aplikasi (mis. lewat TrustProxies middleware) '
                .'agar IP klien asli terbaca, bukan IP proxy/load balancer.');
        }

        return $healthy ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @return array{0: string, 1: string|null}
     */
    private function proxyStatus(): array
    {
        $forwarded = ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '') !== ''
            || ($_SERVER['HTTP_FORWARDED'] ?? '') !== '';

        if (! $forwarded) {
            return ['tidak terdeteksi', null];
        }

        $trusted = Request::getTrustedProxies();

        if ($trusted === []) {
            return ['terdeteksi', 'header forwarded ditemukan tetapi trusted proxies belum dikonfigurasi.'];
        }

        return ['ok', null];
    }
}
