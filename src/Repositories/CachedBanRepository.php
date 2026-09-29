<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Repositories;

use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Persistence\CacheAdapterInterface;
use Ganadev\Shield\Core\Reputation\BanRecord;

/**
 * Hot-path decorator: caches the active ban lookup per IP with a short TTL so
 * the common allow-path does not hit the database on every request (spec 21).
 * All mutating operations invalidate the cached entry for the affected IP.
 *
 * Only the plain array form of a BanRecord is cached (see BanRecord::toArray).
 * Persistent stores serialize whatever they are given, and a serialized domain
 * object breaks as soon as the class cannot be resolved on read, surfacing as
 * __PHP_Incomplete_Class. Any entry that is not a usable array is dropped and
 * re-fetched so a poisoned cache heals itself instead of throwing.
 */
final class CachedBanRepository implements BanRepositoryInterface
{
    private const NULL_SENTINEL = false;

    public function __construct(
        private readonly BanRepositoryInterface $inner,
        private readonly CacheAdapterInterface $cache,
        private readonly int $ttlSeconds,
    ) {}

    public function findActiveByIp(string $ip): ?BanRecord
    {
        $key = $this->key($ip);
        $cached = $this->cache->get($key);

        if ($cached !== null) {
            if ($cached === self::NULL_SENTINEL) {
                return null;
            }

            if (is_array($cached)) {
                try {
                    return BanRecord::fromArray($cached);
                } catch (\Throwable) {
                    $this->cache->delete($key);
                }
            } else {
                // Legacy payload: a serialized domain object (or an
                // __PHP_Incomplete_Class left behind by an earlier release).
                // Discard it instead of returning a value the return type
                // cannot accept, then fall through to the inner repository.
                $this->cache->delete($key);
            }
        }

        $record = $this->inner->findActiveByIp($ip);
        $this->cache->set($key, $record === null ? self::NULL_SENTINEL : $record->toArray(), $this->ttlSeconds);

        return $record;
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        return $this->inner->findLatestByIp($ip);
    }

    public function findById(string $id): ?BanRecord
    {
        return $this->inner->findById($id);
    }

    public function createBan(BanRecord $record): BanRecord
    {
        $created = $this->inner->createBan($record);
        $this->cache->delete($this->key($record->ipAddress));

        return $created;
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        $released = $this->inner->release($ban, $reason, $actor);
        $this->cache->delete($this->key($ban->ipAddress));

        return $released;
    }

    public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        $extended = $this->inner->extend($ban, $expiresAt, $actor);
        $this->cache->delete($this->key($ban->ipAddress));

        return $extended;
    }

    public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $updated = $this->inner->markChallengePassed($ban, $at);
        $this->cache->delete($this->key($ban->ipAddress));

        return $updated;
    }

    public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $updated = $this->inner->touchLastSeen($ban, $at);
        $this->cache->delete($this->key($ban->ipAddress));

        return $updated;
    }

    private function key(string $ip): string
    {
        return 'ban:active:'.$ip;
    }
}
