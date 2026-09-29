<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Trust;

use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Persistence\CacheAdapterInterface;
use Ganadev\Shield\Core\Support\IpCidrMatcher;
use Ganadev\Shield\Core\Trust\CrawlerVerifierInterface;

/**
 * Verifies a crawler claim (User-Agent) against the actual client IP.
 *
 * Strategy (cheapest first):
 *  1. Configured CIDR allowlist for the claimed agent (no DNS, offline).
 *  2. Reverse-DNS: the PTR hostname must end with one of the agent's known
 *     hostname suffixes (e.g. *.googlebot.com).
 *  3. Forward-confirm: the PTR hostname must resolve back to the requesting IP.
 *
 * Results are cached per IP for `bots.verification.ttl_hours` so DNS lookups
 * happen at most once per day per crawler IP.
 *
 * The DNS resolver is injectable for tests; by default it uses gethostbyaddr()
 * and dns_get_record(). When DNS is unavailable, only the CIDR allowlist can
 * confirm a crawler (fail-closed).
 */
final class DnsCrawlerVerifier implements CrawlerVerifierInterface
{
    private const CACHE_PREFIX = 'crawler-verify:';

    private const CACHE_NONE = 'none';

    private readonly ?\Closure $dnsResolver;

    public function __construct(
        private readonly CacheAdapterInterface $cache,
        private readonly ShieldConfig $config,
        ?callable $dnsResolver = null,
    ) {
        $this->dnsResolver = $dnsResolver === null ? null : \Closure::fromCallable($dnsResolver);
    }

    public function verify(string $claimedAgent, string $ip): ?string
    {
        $key = self::CACHE_PREFIX.$ip;

        $cached = $this->cache->get($key);
        if ($cached !== null) {
            return $cached === self::CACHE_NONE ? null : (string) $cached;
        }

        $result = $this->verifyUncached($claimedAgent, $ip);
        $ttl = $this->config->crawlerVerificationTtlHours * 3600;
        $this->cache->set($key, $result ?? self::CACHE_NONE, $ttl);

        return $result;
    }

    private function verifyUncached(string $claimedAgent, string $ip): ?string
    {
        $ranges = $this->config->crawlerIpRanges[$claimedAgent] ?? [];
        if (IpCidrMatcher::inAnyRange($ip, $ranges)) {
            return $claimedAgent;
        }

        $hostname = strtolower($this->resolvePtr($ip));
        if ($hostname === '' || $hostname === strtolower($ip)) {
            return null;
        }

        $suffixes = $this->config->crawlerHostnames[$claimedAgent] ?? [];
        if (! $this->matchesSuffix($hostname, $suffixes)) {
            return null;
        }

        $addresses = $this->resolveAddresses($hostname);

        return in_array($ip, $addresses, true) ? $claimedAgent : null;
    }

    /**
     * @param  list<string>  $suffixes
     */
    private function matchesSuffix(string $hostname, array $suffixes): bool
    {
        foreach ($suffixes as $suffix) {
            $suffix = strtolower(trim($suffix));
            if ($suffix === '') {
                continue;
            }
            if ($hostname === $suffix || str_ends_with($hostname, $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function resolvePtr(string $ip): string
    {
        if ($this->dnsResolver !== null) {
            return (string) ($this->dnsResolver)('ptr', $ip);
        }

        $host = @gethostbyaddr($ip);

        return is_string($host) && $host !== '' ? $host : '';
    }

    /**
     * @return list<string>
     */
    private function resolveAddresses(string $hostname): array
    {
        if ($this->dnsResolver !== null) {
            return array_values((array) ($this->dnsResolver)('a', $hostname));
        }

        $records = @dns_get_record($hostname, DNS_A);
        if ($records === false) {
            return [];
        }

        $addresses = [];
        foreach ($records as $record) {
            if (isset($record['ip']) && is_string($record['ip'])) {
                $addresses[] = $record['ip'];
            }
        }

        return $addresses;
    }
}
