<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Unit;

use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Laravel\Cache\LaravelCacheAdapter;
use Ganadev\Shield\Laravel\Trust\DnsCrawlerVerifier;

/**
 * @param  array<string, mixed>  $config
 */
function makeVerifier(array $config, callable $dns): DnsCrawlerVerifier
{
    $cfg = ShieldConfig::fromArray($config);
    $cache = new LaravelCacheAdapter(app('cache')->store(), 'crawler-test');

    return new DnsCrawlerVerifier($cache, $cfg, $dns);
}

it('verifies a crawler via reverse DNS and forward confirmation', function () {
    $verifier = makeVerifier([], function (string $type, string $value): mixed {
        return match ($type) {
            'ptr' => 'crawl-66-249-79-12.googlebot.com',
            'a' => ['66.249.79.12'],
            default => null,
        };
    });

    expect($verifier->verify('googlebot', '66.249.79.12'))->toBe('googlebot');
});

it('rejects a crawler claim whose PTR does not match the agent hostnames', function () {
    $verifier = makeVerifier([], function (string $type): mixed {
        return $type === 'ptr' ? 'mail.evil-scanner.example' : null;
    });

    expect($verifier->verify('googlebot', '66.249.79.12'))->toBeNull();
});

it('rejects a crawler claim whose PTR hostname does not forward-confirm the IP', function () {
    $verifier = makeVerifier([], function (string $type): mixed {
        return $type === 'ptr' ? 'crawl-66-249-79-12.googlebot.com' : ['198.51.100.99'];
    });

    expect($verifier->verify('googlebot', '66.249.79.12'))->toBeNull();
});

it('verifies a crawler via a configured CIDR range without any DNS call', function () {
    $dnsCalls = 0;
    $verifier = makeVerifier([
        'bots' => [
            'verification' => ['ip_ranges' => ['googlebot' => ['66.249.64.0/19']]],
        ],
    ], function (string $type, string $value) use (&$dnsCalls): mixed {
        $dnsCalls++;

        return null;
    });

    expect($verifier->verify('googlebot', '66.249.79.12'))->toBe('googlebot');
    expect($dnsCalls)->toBe(0);
});

it('fails closed when no PTR record exists', function () {
    $verifier = makeVerifier([], function (string $type): mixed {
        return $type === 'ptr' ? '203.0.113.10' : null;
    });

    expect($verifier->verify('googlebot', '203.0.113.10'))->toBeNull();
});

it('caches a successful verification per IP', function () {
    $dnsCalls = 0;
    $verifier = makeVerifier([], function (string $type, string $value) use (&$dnsCalls): mixed {
        $dnsCalls++;

        return match ($type) {
            'ptr' => 'crawl-66-249-79-12.googlebot.com',
            'a' => ['66.249.79.12'],
            default => null,
        };
    });

    expect($verifier->verify('googlebot', '66.249.79.12'))->toBe('googlebot');
    expect($verifier->verify('googlebot', '66.249.79.12'))->toBe('googlebot');
    expect($dnsCalls)->toBe(2); // ptr + forward for the first lookup only
});

it('caches a failed verification using a sentinel', function () {
    $dnsCalls = 0;
    $verifier = makeVerifier([], function (string $type) use (&$dnsCalls): mixed {
        $dnsCalls++;

        return $type === 'ptr' ? '203.0.113.10' : null;
    });

    expect($verifier->verify('googlebot', '203.0.113.10'))->toBeNull();
    expect($verifier->verify('googlebot', '203.0.113.10'))->toBeNull();
    expect($dnsCalls)->toBe(1);
});
