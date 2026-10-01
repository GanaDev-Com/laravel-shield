<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Console\Commands;

use Ganadev\Shield\Laravel\Support\TrustedProxyInspector;
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
     * Status label plus the warning shown under the table.
     *
     * The dangerous combination is "forwarded headers arrive but nothing is
     * trusted": every client then shares the proxy IP, which defeats IP-based
     * rate limiting and bans. That must be detected even when no forwarded
     * header happens to be present in the current CLI environment, so the
     * configured proxies are read from TrustProxies rather than $_SERVER only.
     *
     * @return array{0: string, 1: string|null}
     */
    private function proxyStatus(): array
    {
        $forwarded = TrustedProxyInspector::forwardedHeaderSeen($_SERVER);
        $proxies = TrustedProxyInspector::configuredProxies();
        $trusted = Request::getTrustedProxies();
        $requestTrusted = $trusted !== [];

        if ($proxies !== null) {
            $status = $proxies === ['*'] ? 'ok (trust semua proxy)' : 'ok';
            $warning = null;
            if (! $forwarded && ! $requestTrusted) {
                $warning = 'trusted proxies dikonfigurasi tetapi belum ada request dengan header forwarded.';
            }

            return [$status, $warning];
        }

        if ($requestTrusted) {
            return ['ok (hanya pada request ini)', null];
        }

        if ($forwarded) {
            return [
                'header forwarded, trusted proxies kosong',
                'header forwarded ditemukan tetapi trusted proxies belum dikonfigurasi. '
                .'Semua klien akan terlihat sebagai IP proxy sehingga rate limit per-IP dan ban tidak efektif.',
            ];
        }

        $appUrl = (string) config('app.url', '');

        if (TrustedProxyInspector::looksDeployedBehindProxy($appUrl)) {
            return [
                'tidak dikonfigurasi (app publik)',
                ' aplikasi berjalan pada host publik ('.$appUrl.') tetapi trusted proxies belum dikonfigurasi. '
                .'Jika ada reverse proxy/Cloudflare di depan aplikasi, konfigurasikan TrustProxies::at() '
                .'agar IP klien asli terbaca.',
            ];
        }

        return ['tidak terdeteksi', null];
    }
}
