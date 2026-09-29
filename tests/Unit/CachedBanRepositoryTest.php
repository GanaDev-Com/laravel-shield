<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Unit;

use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Laravel\Cache\LaravelCacheAdapter;
use Ganadev\Shield\Laravel\Repositories\CachedBanRepository;

function activeBanRecord(string $ip): BanRecord
{
    $now = new \DateTimeImmutable;

    return new BanRecord(
        id: 'ban-1',
        ipAddress: $ip,
        status: BanStatus::Active,
        reason: 'test',
        lastRuleId: null,
        riskScore: 25,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: $now,
        expiresAt: $now->modify('+1 hour'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: $now,
    );
}

it('caches the active ban lookup and skips the inner store on repeat', function () {
    $calls = 0;
    $inner = new class($calls) implements BanRepositoryInterface
    {
        public int $lookups = 0;

        public function findActiveByIp(string $ip): ?BanRecord
        {
            $this->lookups++;

            return activeBanRecord($ip);
        }

        public function findLatestByIp(string $ip): ?BanRecord
        {
            return null;
        }

        public function findById(string $id): ?BanRecord
        {
            return null;
        }

        public function createBan(BanRecord $record): BanRecord
        {
            return $record;
        }

        public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }

        public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }
    };

    $cache = app('cache')->store();
    $repo = new CachedBanRepository($inner, new LaravelCacheAdapter($cache, 'my-app'), 30);

    $first = $repo->findActiveByIp('10.0.0.9');
    $second = $repo->findActiveByIp('10.0.0.9');

    expect($first)->not->toBeNull();
    expect($second)->not->toBeNull();
    expect($inner->lookups)->toBe(1);

    // Second call is served from the cache, so the values must be equivalent.
    expect($second->id)->toBe($first->id);
    expect($second->ipAddress)->toBe($first->ipAddress);
    expect($second->status)->toBe($first->status);

    // The cached entry must be the plain array form, never a live object, so
    // persistent stores cannot hand back __PHP_Incomplete_Class on read.
    $raw = $cache->get('shield:my-app:ban:active:10.0.0.9');
    expect($raw)->toBeArray();
    expect($raw)->toBe($first->toArray());
});

it('stores a plain array that survives a serialize round-trip', function () {
    $inner = new class implements BanRepositoryInterface
    {
        public function findActiveByIp(string $ip): ?BanRecord
        {
            return activeBanRecord($ip);
        }

        public function findLatestByIp(string $ip): ?BanRecord
        {
            return null;
        }

        public function findById(string $id): ?BanRecord
        {
            return null;
        }

        public function createBan(BanRecord $record): BanRecord
        {
            return $record;
        }

        public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }

        public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }
    };

    $cache = app('cache')->store();
    $repo = new CachedBanRepository($inner, new LaravelCacheAdapter($cache, 'round-trip'), 30);

    $repo->findActiveByIp('10.0.0.9');

    $stored = $cache->get('shield:round-trip:ban:active:10.0.0.9');

    // Emulate a persistent store: the value comes back through serialize.
    $rehydrated = unserialize(serialize($stored));

    expect($rehydrated)->toBeArray();
    expect(BanRecord::fromArray($rehydrated))->toBeInstanceOf(BanRecord::class);
});

it('discards a cached payload that is not a usable array and re-fetches from the inner store', function () {
    // An object payload is what older releases wrote. A persistent store hands
    // it back as __PHP_Incomplete_Class, which the return type rejects, so the
    // entry has to be dropped instead of returned.
    $poisoned = unserialize('O:8:"stdClass":0:{}');

    $inner = new class implements BanRepositoryInterface
    {
        public int $lookups = 0;

        public function findActiveByIp(string $ip): ?BanRecord
        {
            $this->lookups++;

            return activeBanRecord($ip);
        }

        public function findLatestByIp(string $ip): ?BanRecord
        {
            return null;
        }

        public function findById(string $id): ?BanRecord
        {
            return null;
        }

        public function createBan(BanRecord $record): BanRecord
        {
            return $record;
        }

        public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }

        public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }
    };

    $cache = app('cache')->store();
    $cache->put('shield:poison:ban:active:10.0.0.9', $poisoned, 30);

    $repo = new CachedBanRepository($inner, new LaravelCacheAdapter($cache, 'poison'), 30);

    $record = $repo->findActiveByIp('10.0.0.9');

    expect($record)->toBeInstanceOf(BanRecord::class);
    expect($inner->lookups)->toBe(1);

    // The bad entry is replaced with the array form.
    expect($cache->get('shield:poison:ban:active:10.0.0.9'))->toBeArray();
});

it('discards a corrupted array payload and re-fetches from the inner store', function () {
    $inner = new class implements BanRepositoryInterface
    {
        public int $lookups = 0;

        public function findActiveByIp(string $ip): ?BanRecord
        {
            $this->lookups++;

            return activeBanRecord($ip);
        }

        public function findLatestByIp(string $ip): ?BanRecord
        {
            return null;
        }

        public function findById(string $id): ?BanRecord
        {
            return null;
        }

        public function createBan(BanRecord $record): BanRecord
        {
            return $record;
        }

        public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }

        public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }
    };

    $cache = app('cache')->store();
    $cache->put('shield:corrupt:ban:active:10.0.0.9', ['status' => 'not-a-status'], 30);

    $repo = new CachedBanRepository($inner, new LaravelCacheAdapter($cache, 'corrupt'), 30);

    $record = $repo->findActiveByIp('10.0.0.9');

    expect($record)->toBeInstanceOf(BanRecord::class);
    expect($record->ipAddress)->toBe('10.0.0.9');
    expect($inner->lookups)->toBe(1);
    expect($cache->get('shield:corrupt:ban:active:10.0.0.9'))->toBeArray();
});

it('caches a null lookup using a sentinel', function () {
    $inner = new class implements BanRepositoryInterface
    {
        public int $lookups = 0;

        public function findActiveByIp(string $ip): ?BanRecord
        {
            $this->lookups++;

            return null;
        }

        public function findLatestByIp(string $ip): ?BanRecord
        {
            return null;
        }

        public function findById(string $id): ?BanRecord
        {
            return null;
        }

        public function createBan(BanRecord $record): BanRecord
        {
            return $record;
        }

        public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }

        public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }
    };

    $repo = new CachedBanRepository($inner, new LaravelCacheAdapter(app('cache')->store(), 'my-app'), 30);

    expect($repo->findActiveByIp('10.0.0.9'))->toBeNull();
    expect($repo->findActiveByIp('10.0.0.9'))->toBeNull();
    expect($inner->lookups)->toBe(1);
});

it('invalidates the cached ban on release', function () {
    $inner = new class implements BanRepositoryInterface
    {
        public int $lookups = 0;

        public ?BanRecord $ban;

        public function findActiveByIp(string $ip): ?BanRecord
        {
            $this->lookups++;

            return $this->ban;
        }

        public function findLatestByIp(string $ip): ?BanRecord
        {
            return null;
        }

        public function findById(string $id): ?BanRecord
        {
            return null;
        }

        public function createBan(BanRecord $record): BanRecord
        {
            $this->ban = $record;

            return $record;
        }

        public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
        {
            $this->ban = null;

            return $ban;
        }

        public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
        {
            return $ban;
        }

        public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            $this->ban = null;

            return $ban;
        }

        public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
        {
            return $ban;
        }
    };

    $repo = new CachedBanRepository($inner, new LaravelCacheAdapter(app('cache')->store(), 'my-app'), 30);

    $repo->createBan(activeBanRecord('10.0.0.9'));
    expect($repo->findActiveByIp('10.0.0.9'))->not->toBeNull();

    $repo->release(activeBanRecord('10.0.0.9'), 'manual', null);

    expect($repo->findActiveByIp('10.0.0.9'))->toBeNull();
    expect($inner->lookups)->toBe(2);
});
