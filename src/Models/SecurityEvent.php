<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $ip_address
 * @property string $host
 * @property string $method
 * @property string|null $raw_uri
 * @property string|null $normalized_uri
 * @property string|null $rule_id
 * @property string|null $category
 * @property string $severity
 * @property int $score_delta
 * @property string $decision
 * @property string|null $intended_decision
 * @property string|null $user_agent
 * @property string|null $referer
 * @property string|null $request_id
 * @property string|null $rule_version
 * @property Carbon $created_at
 */
final class SecurityEvent extends Model
{
    protected $table = 'security_events';

    public $timestamps = false;

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'score_delta' => 'integer',
            'created_at' => 'datetime',
        ];
    }
}
