<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Unit;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;

/**
 * Runs shield:health with a given forwarded-header/proxy configuration and
 * returns the rendered table plus the warning text.
 *
 * @param  array<string, string>  $server  $_SERVER overrides for the request
 * @return array{table: string, warning: string}
 */
/**
 * Request::setTrustedProxies() and TrustProxies::$alwaysTrust* are global
 * statics; without this they leak between cases.
 */
beforeEach(function () {
    Request::setTrustedProxies([], 0);
    TrustProxies::flushState();
});

function runHealthCommand(array $server = []): array
{
    $previous = [];
    foreach ($server as $key => $value) {
        $previous[$key] = $_SERVER[$key] ?? null;
        $_SERVER[$key] = $value;
    }

    try {
        Artisan::call('shield:health');
        $output = Artisan::output();

        return [
            'table' => $output,
            'warning' => $output,
        ];
    } finally {
        foreach ($previous as $key => $value) {
            if ($value === null) {
                unset($_SERVER[$key]);
            } else {
                $_SERVER[$key] = $value;
            }
        }
    }
}

it('reports no forwarded headers as an unconfigured proxy', function () {
    $result = runHealthCommand();

    expect($result['table'])->toContain('tidak terdeteksi')
        ->and($result['warning'])->not->toContain('Peringatan trusted proxy');
});

it('warns when the app runs on a public host without trusted proxies', function () {
    config()->set('app.url', 'https://shop.example.com');

    $result = runHealthCommand();

    expect($result['warning'])
        ->toContain('Peringatan trusted proxy')
        ->toContain('trusted proxies belum dikonfigurasi');
});

it('does not warn on a local host without trusted proxies', function () {
    config()->set('app.url', 'http://localhost');

    $result = runHealthCommand();

    expect($result['warning'])->not->toContain('Peringatan trusted proxy');
});

it('warns when forwarded headers are present but trusted proxies are empty', function () {
    Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

    $result = runHealthCommand([
        'HTTP_X_FORWARDED_FOR' => '203.0.113.7',
    ]);

    expect($result['warning'])->toContain('Peringatan trusted proxy');
});

it('reports forwarded headers as ok when trusted proxies are configured', function () {
    Request::setTrustedProxies(['203.0.113.0/24'], Request::HEADER_X_FORWARDED_FOR);
    TrustProxies::at('203.0.113.0/24');

    $result = runHealthCommand([
        'HTTP_X_FORWARDED_FOR' => '203.0.113.7',
    ]);

    expect($result['warning'])->not->toContain('Peringatan trusted proxy');
});

it('reads proxies configured through TrustProxies even without a forwarded request', function () {
    TrustProxies::at('10.0.0.0/8');

    $result = runHealthCommand();

    expect($result['warning'])->not->toContain('Peringatan trusted proxy');
});
