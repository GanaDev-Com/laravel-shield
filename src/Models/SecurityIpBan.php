<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $ip_address
 * @property string $status
 * @property string $reason
 * @property string|null $last_rule_id
 * @property int $risk_score
 * @property int $violation_count
 * @property int $offense_count
 * @property Carbon|null $banned_at
 * @property Carbon|null $expires_at
 * @property Carbon|null $released_at
 * @property Carbon|null $challenge_passed_at
 * @property Carbon|null $last_seen_at
 * @property array<string, mixed>|null $metadata
 */
final class SecurityIpBan extends Model
{
    protected $table = 'security_ip_bans';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'risk_score' => 'integer',
            'violation_count' => 'integer',
            'offense_count' => 'integer',
            'banned_at' => 'datetime',
            'expires_at' => 'datetime',
            'released_at' => 'datetime',
            'challenge_passed_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'metadata' => 'array',
        ];
    }
}
