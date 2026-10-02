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
    /**
     * A documented Googlebot address whose reverse DNS is stable, used only to
     * prove the resolver can answer PTR queries at all.
     */
    private const PROBE_IP = '66.249.66.1';

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
        [$crawlerStatus, $crawlerWarning] = $this->crawlerVerificationStatus();

        $this->table(
            ['Component', 'Status'],
            [
                ['Database', $dbStatus],
                ['Cache', $cacheStatus],
                ['Rule engine', 'ok'],
                ['Trusted proxy', $proxyStatus],
                ['Crawler verification', $crawlerStatus],
            ],
        );

        if ($proxyWarning !== null) {
            $this->newLine();
            $this->warn('Peringatan trusted proxy: '.$proxyWarning);
            $this->line('Konfigurasikan trusted proxies di aplikasi (mis. lewat TrustProxies middleware) '
                .'agar IP klien asli terbaca, bukan IP proxy/load balancer.');
        }

        if ($crawlerWarning !== null) {
            $this->newLine();
            $this->warn('Peringatan crawler verification: '.$crawlerWarning);
        }

        return $healthy ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Probes the reverse-DNS path that DnsCrawlerVerifier relies on. Without
     * this row an app whose resolver cannot do PTR lookups still reports a
     * healthy Shield while every real crawler is scored as an unverified
     * claim, which is a silent SEO outage.
     *
     * The probe is best effort on purpose: it must never change the exit code,
     * because DNS availability is an environment property rather than a Shield
     * defect, and a failing resolver in CI would otherwise fail the suite.
     *
     * @return array{0: string, 1: string|null}
     */
    private function crawlerVerificationStatus(): array
    {
        if (! (bool) config('shield.bots.verification.enabled', true)) {
            return ['dimatikan (bots.verification.enabled = false)', null];
        }

        if (! function_exists('gethostbyaddr')) {
            return [
                'tidak dapat diuji',
                'fungsi gethostbyaddr() tidak tersedia, sehingga reverse DNS tidak akan bekerja.',
            ];
        }

        $hostname = @gethostbyaddr(self::PROBE_IP);
        $looksLikeCrawler = is_string($hostname) && $hostname !== self::PROBE_IP
            && (str_contains(strtolower($hostname), 'googlebot')
                || str_contains(strtolower($hostname), 'google.com'));

        if ($looksLikeCrawler) {
            return ['ok (reverse DNS berfungsi)', null];
        }

        return [
            'resolver tidak mengembalikan PTR',
            'reverse DNS untuk IP Googlebot yang dikenal ('.self::PROBE_IP.') tidak menghasilkan hostname yang '
            .'diharapkan. Jika resolver aplikasi memang tidak punya akses internet, ini normal; tetapi kalau '
            .'seharusnya ada akses, maka verifikasi crawler akan selalu gagal dan crawler asli akan '
            .'dianggap sebagai klaim yang belum terverifikasi. Periksa firewall keluar dan konfigurasi DNS.',
        ];
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
