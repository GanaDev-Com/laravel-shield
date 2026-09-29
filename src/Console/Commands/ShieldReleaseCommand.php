<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Console\Commands;

use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Laravel\Support\InputValue;
use Illuminate\Console\Command;

final class ShieldReleaseCommand extends Command
{
    protected $signature = 'shield:release {ip : IP address to unblock} {--reason=manual_release}';

    protected $description = 'Release an active ban for an IP address.';

    public function handle(ShieldEngine $engine): int
    {
        $ip = (new InputValue)->string($this->argument('ip'));
        if ($ip === null) {
            $this->error('A valid IP address argument is required.');

            return self::FAILURE;
        }

        $reason = $this->option('reason');
        if (! is_string($reason) || $reason === '') {
            $reason = 'manual_release';
        }

        $released = $engine->releaseBan($ip, $reason, 'cli:'.get_current_user());

        if (! $released) {
            $this->error('No active ban found for that IP.');

            return self::FAILURE;
        }

        $this->info('Ban released.');

        return self::SUCCESS;
    }
}
