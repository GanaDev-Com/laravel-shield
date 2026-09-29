<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Cache;

use Ganadev\Shield\Core\Persistence\CacheAdapterInterface;
use Illuminate\Contracts\Cache\Repository;

final class LaravelCacheAdapter implements CacheAdapterInterface
{
    public function __construct(
        private readonly Repository $cache,
        private readonly string $appId,
    ) {}

    public function get(string $key): mixed
    {
        return $this->cache->get($this->key($key));
    }

    public function set(string $key, mixed $value, int $ttlSeconds): bool
    {
        $this->cache->put($this->key($key), $value, $ttlSeconds);

        return true;
    }

    public function delete(string $key): bool
    {
        return $this->cache->forget($this->key($key));
    }

    public function has(string $key): bool
    {
        return $this->cache->has($this->key($key));
    }

    public function increment(string $key, int $ttlSeconds): int
    {
        $fullKey = $this->key($key);

        if (! $this->cache->has($fullKey)) {
            $this->cache->put($fullKey, 0, $ttlSeconds);
        }

        return (int) $this->cache->increment($fullKey, 1);
    }

    private function key(string $key): string
    {
        return 'shield:'.$this->appId.':'.$key;
    }
}
