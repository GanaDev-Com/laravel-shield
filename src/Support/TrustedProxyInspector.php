<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Support;

use Illuminate\Http\Middleware\TrustProxies;

/**
 * Reads the trusted-proxy configuration that Laravel stores in a protected
 * static on TrustProxies. There is no public getter, and
 * Request::getTrustedProxies() only reflects the current request, so from a
 * CLI process it is always empty. Reading the static is the only way to answer
 * "is a reverse proxy configured?" from artisan or during boot.
 */
final class TrustedProxyInspector
{
    /**
     * @return array<string>|null null when no explicit proxies are configured
     */
    public static function configuredProxies(): ?array
    {
        /** @var mixed $proxies */
        $proxies = self::readProxies();

        if ($proxies === '*') {
            return ['*'];
        }

        if (! is_array($proxies)) {
            return null;
        }

        $list = array_values(array_filter(array_map('strval', $proxies), static fn (string $p): bool => $p !== ''));

        return $list === [] ? null : $list;
    }

    public static function hasConfiguredProxies(): bool
    {
        return self::configuredProxies() !== null;
    }

    public static function trustsAllProxies(): bool
    {
        return self::readProxies() === '*';
    }

    /**
     * True when the app is reachable on a public host, i.e. it is very likely
     * sitting behind a reverse proxy, load balancer or CDN.
     */
    public static function looksDeployedBehindProxy(string $appUrl): bool
    {
        $host = parse_url($appUrl, PHP_URL_HOST);
        if (! is_string($host) || $host === '') {
            return false;
        }

        return ! in_array(strtolower($host), ['localhost', '127.0.0.1', '::1', '0.0.0.0'], true);
    }

    /**
     * @param  array<string, string>  $server
     */
    public static function forwardedHeaderSeen(array $server): bool
    {
        foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $key) {
            if (($server[$key] ?? '') !== '') {
                return true;
            }
        }

        return false;
    }

    private static function readProxies(): mixed
    {
        return \Closure::bind(
            static fn (): mixed => TrustProxies::$alwaysTrustProxies ?? null,
            null,
            TrustProxies::class,
        )();
    }
}
