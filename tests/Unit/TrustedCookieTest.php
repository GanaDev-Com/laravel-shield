<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Unit;

use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Laravel\Trust\LaravelTrustedCookie;

it('issues a cookie that validates for the same request context', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10', ['user-agent' => 'Mozilla/5.0']);

    $token = $cookie->issue($context, 60);

    expect($cookie->validate($token, $context))->toBeTrue();
});

it('rejects a tampered cookie', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10');

    expect($cookie->validate('garbage'.$cookie->issue($context, 60), $context))->toBeFalse();
});

it('rejects a cookie from a different user agent', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10', ['user-agent' => 'Mozilla/5.0']);

    $token = $cookie->issue($context, 60);
    $other = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10', ['user-agent' => 'python-requests']);

    expect($cookie->validate($token, $other))->toBeFalse();
});

it('accepts a cookie from the same coarse network prefix', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10');

    $token = $cookie->issue($context, 60);
    $natSibling = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.77');

    expect($cookie->validate($token, $natSibling))->toBeTrue();
});

it('rejects a cookie from an unrelated network prefix', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10');

    $token = $cookie->issue($context, 60);
    $other = RequestContext::create('/home', 'GET', 'example.test', '198.51.100.20');

    expect($cookie->validate($token, $other))->toBeFalse();
});

it('rejects an expired cookie', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10');

    $token = $cookie->issue($context, -1);

    expect($cookie->validate($token, $context))->toBeFalse();
});

it('exposes a stable cookie name', function () {
    expect(app(LaravelTrustedCookie::class)->name())->toBe('shield_trusted');
});

it('rejects a cookie that arrives already decrypted', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10', ['user-agent' => 'Mozilla/5.0']);

    // What Laravel hands over once EncryptCookies in the web group has run.
    $plaintext = (string) json_encode(['exp' => time() + 3600, 'ua' => 'x', 'ip' => '203.0.113.0']);

    expect($cookie->validate($plaintext, $context))->toBeFalse();
});

it('still accepts a properly encrypted cookie after seeing a decrypted one', function () {
    $cookie = app(LaravelTrustedCookie::class);
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10', ['user-agent' => 'Mozilla/5.0']);

    $cookie->validate('{"exp":1}', $context);
    $token = $cookie->issue($context, 60);

    expect($cookie->validate($token, $context))->toBeTrue();
});
