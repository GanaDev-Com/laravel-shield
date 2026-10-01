<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Integration;

use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Laravel\Http\Controllers\AdminController;
use Ganadev\Shield\Laravel\Models\SecurityIpBan;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

function adminBan(): SecurityIpBan
{
    return SecurityIpBan::query()->create([
        'ip_address' => '10.9.9.9',
        'status' => BanStatus::Active->value,
        'reason' => 'test ban',
        'risk_score' => 25,
        'offense_count' => 1,
        'banned_at' => now(),
        'expires_at' => now()->addHour(),
        'last_seen_at' => now(),
    ]);
}

function adminUser(): User
{
    $user = new class extends User
    {
        public $id = 1;
    };
    $user->id = 1;

    return $user;
}

it('forbids release when the configured gate denies', function () {
    config()->set('shield.admin.authorize', 'shield.manage');
    Gate::define('shield.manage', fn () => false);

    $ban = adminBan();
    $request = Request::create('/shield/bans/'.$ban->id.'/release', 'POST');
    $request->setUserResolver(fn () => adminUser());

    $response = app(AdminController::class)->release($request, (string) $ban->id);

    expect($response->getStatusCode())->toBe(403);
    expect($ban->fresh()->status)->toBe(BanStatus::Active->value);
});

it('allows release when the configured gate passes', function () {
    config()->set('shield.admin.authorize', 'shield.manage');
    Gate::define('shield.manage', fn () => true);

    $ban = adminBan();
    $request = Request::create('/shield/bans/'.$ban->id.'/release', 'POST');
    $request->setUserResolver(fn () => adminUser());

    $response = app(AdminController::class)->release($request, (string) $ban->id);

    expect($response->getStatusCode())->toBe(200);
    expect($ban->fresh()->status)->toBe(BanStatus::Released->value);
});

it('allows admin actions when no authorize gate is configured', function () {
    config()->set('shield.admin.authorize', '');

    $ban = adminBan();
    $request = Request::create('/shield/bans/'.$ban->id.'/release', 'POST');
    $request->setUserResolver(fn () => adminUser());

    $response = app(AdminController::class)->release($request, (string) $ban->id);

    expect($response->getStatusCode())->toBe(200);
});

it('flags a trusted proxy warning when forwarded headers are present but proxies are unconfigured', function () {
    $request = Request::create('/shield/health', 'GET', [], [], [], ['HTTP_X_FORWARDED_FOR' => '10.0.0.1']);

    $data = json_decode(app(AdminController::class)->health($request)->getContent(), true, 512, JSON_THROW_ON_ERROR);

    expect($data['trusted_proxy_warning'])->not->toBeNull();
});

it('does not warn about trusted proxies when no forwarded headers are present', function () {
    $request = Request::create('/shield/health', 'GET');

    $data = json_decode(app(AdminController::class)->health($request)->getContent(), true, 512, JSON_THROW_ON_ERROR);

    expect($data['trusted_proxy_warning'])->toBeNull();
});

it('warns when the admin panel is enabled without an authorize gate', function () {
    config()->set('shield.admin.enabled', true);
    config()->set('shield.admin.authorize', '');

    $request = Request::create('/shield/health', 'GET');

    $data = json_decode(app(AdminController::class)->health($request)->getContent(), true, 512, JSON_THROW_ON_ERROR);

    expect($data['admin_authorize_warning'])->not->toBeNull();
});

it('does not warn about admin authorization when a gate is configured', function () {
    config()->set('shield.admin.enabled', true);
    config()->set('shield.admin.authorize', 'shield.manage');
    Gate::define('shield.manage', fn () => true);

    $request = Request::create('/shield/health', 'GET');
    $request->setUserResolver(fn () => adminUser());

    $data = json_decode(app(AdminController::class)->health($request)->getContent(), true, 512, JSON_THROW_ON_ERROR);

    expect($data['admin_authorize_warning'])->toBeNull();
});

it('does not warn about admin authorization when the panel is disabled', function () {
    config()->set('shield.admin.enabled', false);
    config()->set('shield.admin.authorize', '');

    $request = Request::create('/shield/health', 'GET');

    $data = json_decode(app(AdminController::class)->health($request)->getContent(), true, 512, JSON_THROW_ON_ERROR);

    expect($data['admin_authorize_warning'])->toBeNull();
});
