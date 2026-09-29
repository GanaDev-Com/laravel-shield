<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Dibangkitkan setiap kali request diblokir, sehingga aplikasi bisa mendengarkan
 * dan mengirim alerting (Slack/Telegram/dll) tanpa core bergantung pada provider.
 */
final class ShieldBlocked
{
    use Dispatchable;

    public function __construct(
        public readonly string $ip,
        public readonly string $ruleId,
        public readonly string $reason,
        public readonly int $score,
        public readonly string $uri,
        public readonly string $method,
    ) {}
}
