<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Unit;

use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Laravel\Cache\LaravelCacheAdapter;
use Ganadev\Shield\Laravel\Challenge\NullTestDriver;
use Ganadev\Shield\Laravel\Support\ShieldResolver;

it('namespaces cache keys with the app id', function () {
    $adapter = new LaravelCacheAdapter(app('cache')->store(), 'my-app');
    $adapter->set('ban:1.2.3.4', ['status' => 'active'], 60);

    expect(app('cache')->store()->get('shield:my-app:ban:1.2.3.4'))->toBe(['status' => 'active']);
    expect(app('cache')->store()->get('ban:1.2.3.4'))->toBeNull();
});

it('increments counters atomically when supported', function () {
    $adapter = new LaravelCacheAdapter(app('cache')->store(), 'my-app');

    expect($adapter->increment('counters:x', 60))->toBe(1);
    expect($adapter->increment('counters:x', 60))->toBe(2);
});

it('resets the counter when the window expires', function () {
    $adapter = new LaravelCacheAdapter(app('cache')->store(), 'my-app');

    expect($adapter->increment('counters:burst', 60))->toBe(1);
    expect($adapter->increment('counters:burst', 60))->toBe(2);

    app('cache')->store()->forget('shield:my-app:counters:burst');

    expect($adapter->increment('counters:burst', 60))->toBe(1);
});

it('supports delete and has operations', function () {
    $adapter = new LaravelCacheAdapter(app('cache')->store(), 'my-app');

    $adapter->set('k', 'v', 60);
    expect($adapter->has('k'))->toBeTrue();
    expect($adapter->delete('k'))->toBeTrue();
    expect($adapter->has('k'))->toBeFalse();
});

it('null test driver is deterministic', function () {
    $driver = new NullTestDriver;
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10');

    expect($driver->name())->toBe('null');
    expect($driver->verify('test-token', $context)->passed)->toBeTrue();
    expect($driver->verify('wrong', $context)->passed)->toBeFalse();
});

it('resolves a challenge driver from the container', function () {
    expect(app(ChallengeDriverInterface::class))->toBeInstanceOf(ChallengeDriverInterface::class);
});

it('treats an env-null driver value as the null test driver', function () {
    config()->set('shield.challenge.driver', '');
    $resolver = app(ShieldResolver::class);

    expect($resolver->challengeDriver())->toBeInstanceOf(NullTestDriver::class);

    config()->set('shield.challenge.driver', 'null');
    expect($resolver->challengeDriver())->toBeInstanceOf(NullTestDriver::class);
});
