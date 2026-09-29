<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Repositories;

use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Persistence\EventRepositoryInterface;
use Ganadev\Shield\Laravel\Models\SecurityEvent as SecurityEventModel;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;

final class EloquentEventRepository implements EventRepositoryInterface
{
    public function record(SecurityEvent $event): void
    {
        SecurityEventModel::query()->create($event->toArray());
    }

    public function pruneOlderThan(\DateTimeImmutable $cutoff): int
    {
        return SecurityEventModel::query()
            ->where('created_at', '<', $cutoff)
            ->delete();
    }

    /**
     * @param  array<string, mixed>  $filters
     * @return LengthAwarePaginator<int, SecurityEventModel>
     */
    public function paginate(array $filters = [], int $perPage = 50)
    {
        return $this->filteredQuery($filters)->paginate($perPage);
    }

    /**
     * @param  array<string, mixed>  $filters
     */
    /**
     * @param  array<string, mixed>  $filters
     * @return Builder<SecurityEventModel>
     */
    private function filteredQuery(array $filters): Builder
    {
        $query = SecurityEventModel::query();

        if (! empty($filters['ip'])) {
            $query->where('ip_address', (string) $filters['ip']);
        }
        if (! empty($filters['host'])) {
            $query->where('host', (string) $filters['host']);
        }
        if (! empty($filters['rule_id'])) {
            $query->where('rule_id', (string) $filters['rule_id']);
        }
        if (! empty($filters['severity'])) {
            $query->where('severity', (string) $filters['severity']);
        }
        if (! empty($filters['decision'])) {
            $query->where('decision', (string) $filters['decision']);
        }

        return $query->latest('created_at');
    }
}
