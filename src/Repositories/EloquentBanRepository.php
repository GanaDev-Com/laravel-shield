<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Repositories;

use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Laravel\Models\SecurityIpBan;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;

final class EloquentBanRepository implements BanRepositoryInterface
{
    public function findActiveByIp(string $ip): ?BanRecord
    {
        $model = $this->query()
            ->where('ip_address', $ip)
            ->whereIn('status', [BanStatus::Active->value, BanStatus::ManualBlock->value])
            ->where(function (Builder $query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->latest('banned_at')
            ->first();

        if (! $model instanceof SecurityIpBan) {
            return null;
        }

        return $this->toRecord($model);
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        $model = $this->query()
            ->where('ip_address', $ip)
            ->latest('banned_at')
            ->first();

        if (! $model instanceof SecurityIpBan) {
            return null;
        }

        return $this->toRecord($model);
    }

    public function findById(string $id): ?BanRecord
    {
        $model = $this->query()->find($id);

        if (! $model instanceof SecurityIpBan) {
            return null;
        }

        return $this->toRecord($model);
    }

    public function createBan(BanRecord $record): BanRecord
    {
        $model = $this->query()->updateOrCreate(
            ['ip_address' => $record->ipAddress],
            [
                'status' => $record->status->value,
                'reason' => $record->reason,
                'last_rule_id' => $record->lastRuleId,
                'risk_score' => $record->riskScore,
                'violation_count' => $record->violationCount,
                'offense_count' => $record->offenseCount,
                'banned_at' => $record->bannedAt,
                'expires_at' => $record->expiresAt,
                'released_at' => $record->releasedAt,
                'challenge_passed_at' => $record->challengePassedAt,
                'last_seen_at' => $record->lastSeenAt,
                'metadata' => $record->metadata,
            ],
        );

        return $this->toRecord($model);
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        $model = $this->query()->findOrFail($ban->id);
        $model->update([
            'status' => BanStatus::Released->value,
            'released_at' => now(),
            'metadata' => array_merge($model->metadata ?? [], [
                'release_reason' => $reason,
                'released_by' => $actor ?? 'system',
            ]),
        ]);

        return $this->toRecord($model);
    }

    public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        $model = $this->query()->findOrFail($ban->id);
        $model->update([
            'expires_at' => $expiresAt,
            'metadata' => array_merge($model->metadata ?? [], [
                'extended_by' => $actor ?? 'system',
            ]),
        ]);

        return $this->toRecord($model);
    }

    public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $model = $this->query()->findOrFail($ban->id);
        $model->update([
            'status' => BanStatus::Released->value,
            'released_at' => $at,
            'challenge_passed_at' => $at,
        ]);

        return $this->toRecord($model);
    }

    public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $model = $this->query()->findOrFail($ban->id);
        $model->update(['last_seen_at' => $at]);

        return $this->toRecord($model);
    }

    /**
     * @param  array<string, mixed>  $filters
     * @return LengthAwarePaginator<int, SecurityIpBan>
     */
    public function paginate(array $filters = [], int $perPage = 50)
    {
        $query = $this->query();

        if (! empty($filters['ip'])) {
            $query->where('ip_address', (string) $filters['ip']);
        }
        if (! empty($filters['status'])) {
            $query->where('status', (string) $filters['status']);
        }
        if (($filters['active'] ?? false) === true) {
            $query->whereIn('status', [BanStatus::Active->value, BanStatus::ManualBlock->value]);
        }

        return $query->latest('banned_at')->paginate($perPage);
    }

    /**
     * @return Builder<SecurityIpBan>
     */
    private function query(): Builder
    {
        return SecurityIpBan::query();
    }

    private function toRecord(SecurityIpBan $model): BanRecord
    {
        $status = BanStatus::from((string) $model->status);

        return new BanRecord(
            id: (string) $model->getKey(),
            ipAddress: (string) $model->ip_address,
            status: $status,
            reason: (string) $model->reason,
            lastRuleId: $model->last_rule_id !== null ? (string) $model->last_rule_id : null,
            riskScore: (int) $model->risk_score,
            violationCount: (int) $model->violation_count,
            offenseCount: (int) $model->offense_count,
            bannedAt: $this->toDateTime($model->banned_at),
            expiresAt: $this->toDateTimeNullable($model->expires_at),
            releasedAt: $this->toDateTimeNullable($model->released_at),
            challengePassedAt: $this->toDateTimeNullable($model->challenge_passed_at),
            lastSeenAt: $this->toDateTime($model->last_seen_at),
            metadata: is_array($model->metadata) ? $model->metadata : null,
        );
    }

    private function toDateTime(mixed $value): \DateTimeImmutable
    {
        if ($value instanceof \DateTimeImmutable) {
            return $value;
        }
        if ($value instanceof \DateTimeInterface) {
            return \DateTimeImmutable::createFromInterface($value);
        }

        return new \DateTimeImmutable((string) $value);
    }

    private function toDateTimeNullable(mixed $value): ?\DateTimeImmutable
    {
        return $value === null ? null : $this->toDateTime($value);
    }
}
