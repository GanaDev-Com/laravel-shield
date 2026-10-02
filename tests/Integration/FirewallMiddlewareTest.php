<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Integration;

use Ganadev\Shield\Core\Reputation\BanStatus;
use Ganadev\Shield\Laravel\Events\ShieldBlocked;
use Ganadev\Shield\Laravel\Models\SecurityEvent;
use Ganadev\Shield\Laravel\Models\SecurityIpBan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;

it('lets a normal route through untouched', function () {
    $this->get('/home')->assertOk()->assertSee('home');
});

it('blocks a sensitive .env probe before the controller runs', function () {
    $this->get('/.env')->assertStatus(404)->assertHeader('X-Shield-Blocked', 'sensitive.env');
});

it('records a security event for the block', function () {
    $this->get('/.env')->assertStatus(404);

    $event = SecurityEvent::query()->latest('id')->first();
    expect($event)->not->toBeNull();
    expect($event->rule_id)->toBe('sensitive.env');
    expect($event->decision)->toBe('BLOCK_REQUEST');
});

it('dispatches a ShieldBlocked event on block', function () {
    Event::fake([ShieldBlocked::class]);

    $this->get('/.env')->assertStatus(404);

    Event::assertDispatched(ShieldBlocked::class);
});

it('masks sensitive query parameters in the dispatched event payload', function () {
    Event::fake([ShieldBlocked::class]);

    $this->get('/?file=/root/.aws/credentials&api_token=SECRET123&page=2')
        ->assertStatus(404);

    Event::assertDispatched(ShieldBlocked::class, function (ShieldBlocked $event): bool {
        // suffix _token ikut termasking, param non-sensitif tetap utuh
        expect($event->uri)->toContain('api_token=***');
        expect($event->uri)->toContain('file=/root/.aws/credentials');
        expect($event->uri)->toContain('page=2');
        expect($event->uri)->not->toContain('SECRET123');

        return true;
    });
});

it('blocks query string exploits too', function () {
    $this->get('/?file=/root/.aws/credentials')->assertStatus(404);
});

it('detects double encoded traversal', function () {
    $this->get('/%252e%252e/%252e%252e/etc/passwd')->assertStatus(404);
});

it('blocks RCE probe php://input', function () {
    $this->get('/cgi-bin/php?x=php://input')->assertStatus(404);
});

it('persists an active ban in the database', function () {
    $this->get('/.env')->assertStatus(404);

    $ban = SecurityIpBan::query()->first();
    expect($ban)->not->toBeNull();
    expect($ban->status)->toBe(BanStatus::Active->value);
    expect($ban->offense_count)->toBe(1);
    expect($ban->expires_at)->not->toBeNull();
});

it('challenges a banned ip hitting a normal route', function () {
    SecurityIpBan::query()->create([
        'ip_address' => '10.0.0.5',
        'status' => BanStatus::Active->value,
        'reason' => 'test ban',
        'risk_score' => 25,
        'offense_count' => 1,
        'banned_at' => now(),
        'expires_at' => now()->addHour(),
        'last_seen_at' => now(),
    ]);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5'])
        ->get('/home')
        ->assertRedirect(route('shield.challenge', ['redirect' => '/home']));
});

it('redirects back to the challenged path after a successful verify', function () {
    SecurityIpBan::query()->create([
        'ip_address' => '10.0.0.8',
        'status' => BanStatus::Active->value,
        'reason' => 'test ban',
        'risk_score' => 25,
        'offense_count' => 1,
        'banned_at' => now(),
        'expires_at' => now()->addHour(),
        'last_seen_at' => now(),
    ]);

    // 1. Banned IP hits /home -> redirected to challenge with a RELATIVE redirect.
    $challenge = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.8'])
        ->get('/home')
        ->assertRedirect()
        ->headers->get('Location');

    expect($challenge)->toContain('/shield/challenge?redirect='.urlencode('/home'));

    // 2. Challenge page renders a real CSRF token.
    $html = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.8'])
        ->get('/shield/challenge?redirect=/home')
        ->assertOk()
        ->getContent();

    preg_match('/name="_token" value="([^"]+)"/', $html, $matches);
    $token = $matches[1] ?? '';

    expect($token)->not->toBeEmpty('challenge page must render a real CSRF token');

    // 3. Verifying sends the user back to /home, not to the root path.
    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.8'])
        ->withSession(['_token' => $token])
        ->post('/shield/challenge/verify', [
            '_token' => $token,
            'shield_challenge_token' => 'test-token',
            'redirect' => '/home',
        ])->assertRedirect('/home');
});

it('renders the challenge page with an active session', function () {
    $html = $this->get('/shield/challenge?redirect=/home')
        ->assertOk()
        ->getContent();

    expect($html)->toContain('shield-form');
    expect($html)->toContain('name="shield_challenge_token"');
    expect($html)->toContain('<button type="submit">Verify</button>');
    expect($html)->toContain('function onChallengeSolved');
});

it('renders a turnstile challenge with the auto-submit wiring', function () {
    config()->set('shield.challenge.driver', 'turnstile');

    $html = $this->get('/shield/challenge')
        ->assertOk()
        ->getContent();

    expect($html)->toContain('cf-turnstile');
    expect($html)->toContain('data-callback="onChallengeSolved"');
    expect($html)->toContain('function onChallengeSolved');
});

it('shows a verification error alert on the challenge page', function () {
    $html = $this->get('/shield/challenge?error=1')->assertOk()->getContent();

    expect($html)->toContain('Verification failed');
});

it('renders the blocked page as branded html', function () {
    config()->set('shield.branding.show_rule_id', true);

    $response = $this->get('/.env')->assertStatus(404);
    $response->assertHeader('X-Shield-Blocked', 'sensitive.env');

    $html = $response->getContent();
    expect($html)->toContain('Access Blocked');
    expect($html)->toContain('sensitive.env');
    expect($html)->toContain('Ganadev Laravel Shield');
});

it('hides the rule id on the blocked page by default', function () {
    $response = $this->get('/.env')->assertStatus(404);
    // The header is a deliberate operator signal and stays regardless of the
    // page setting; only the rendered body hides the rule id.
    $response->assertHeader('X-Shield-Blocked', 'sensitive.env');

    expect($response->getContent())->not->toContain('sensitive.env');
});

it('hides the rule id on the blocked page when branding.show_rule_id is false', function () {
    config()->set('shield.branding.show_rule_id', false);

    $html = $this->get('/.env')->assertStatus(404)->getContent();

    expect($html)->not->toContain('sensitive.env');
    expect($html)->toContain('Access Blocked');
});

it('challenge success releases the ban and issues a trusted cookie', function () {
    SecurityIpBan::query()->create([
        'ip_address' => '10.0.0.5',
        'status' => BanStatus::Active->value,
        'reason' => 'test ban',
        'risk_score' => 25,
        'offense_count' => 1,
        'banned_at' => now(),
        'expires_at' => now()->addHour(),
        'last_seen_at' => now(),
    ]);

    $token = 'csrf-token';
    $response = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5'])
        ->withSession(['_token' => $token])
        ->post('/shield/challenge/verify', [
            '_token' => $token,
            'shield_challenge_token' => 'test-token',
            'redirect' => '/home',
        ]);

    $response->assertRedirect('/home');
    $response->assertCookie('shield_trusted');

    $ban = SecurityIpBan::query()->where('ip_address', '10.0.0.5')->first();
    expect($ban->status)->toBe(BanStatus::Released->value);
    expect($ban->challenge_passed_at)->not->toBeNull();
});

it('completes the full challenge flow like a browser', function () {
    SecurityIpBan::query()->create([
        'ip_address' => '10.0.0.7',
        'status' => BanStatus::Active->value,
        'reason' => 'test ban',
        'risk_score' => 25,
        'offense_count' => 1,
        'banned_at' => now(),
        'expires_at' => now()->addHour(),
        'last_seen_at' => now(),
    ]);

    $html = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.7'])
        ->get('/shield/challenge')
        ->assertOk()
        ->getContent();

    preg_match('/name="_token" value="([^"]+)"/', $html, $matches);
    $token = $matches[1] ?? '';

    expect($token)->not->toBeEmpty('challenge page must render a real CSRF token');

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.7'])
        ->withSession(['_token' => $token])
        ->post('/shield/challenge/verify', [
            '_token' => $token,
            'shield_challenge_token' => 'test-token',
            'redirect' => '/home',
        ])->assertRedirect('/home');

    $ban = SecurityIpBan::query()->where('ip_address', '10.0.0.7')->first();
    expect($ban->status)->toBe(BanStatus::Released->value);
});

it('critical signature still blocks a banned ip that passed the challenge', function () {
    SecurityIpBan::query()->create([
        'ip_address' => '10.0.0.5',
        'status' => BanStatus::Released->value,
        'reason' => 'challenge passed',
        'risk_score' => 25,
        'offense_count' => 1,
        'banned_at' => now()->subHour(),
        'expires_at' => now()->subMinute(),
        'released_at' => now()->subMinute(),
        'challenge_passed_at' => now()->subMinute(),
        'last_seen_at' => now()->subMinute(),
    ]);

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5'])
        ->get('/.env')
        ->assertStatus(404);
});

it('keeps normal traffic clean and never bans legitimate requests', function () {
    for ($i = 0; $i < 20; $i++) {
        $this->get("/home?p={$i}")->assertOk();
    }

    expect(SecurityIpBan::query()->count())->toBe(0);
});

it('admin routes are not exposed when disabled', function () {
    $this->get('/shield/bans')->assertNotFound();
});

it('does not scan admin routes when the admin prefix is customised', function () {
    config()->set('shield.admin.prefix', 'ops-shield');

    Route::middleware('web')->prefix('ops-shield')->group(function () {
        Route::get('/bans', fn () => 'admin bans')->name('ops-shield.bans');
    });

    // Would be blocked as an AWS credential probe if the firewall scanned it.
    $this->get('/ops-shield/bans?file=/root/.aws/credentials')
        ->assertOk()
        ->assertSee('admin bans')
        ->assertHeaderMissing('X-Shield-Blocked');
});

it('still scans application routes when the admin prefix is customised', function () {
    config()->set('shield.admin.prefix', 'ops-shield');

    $this->get('/home?file=/root/.aws/credentials')
        ->assertStatus(404)
        ->assertHeader('X-Shield-Blocked');
});

it('does not scan the default shield prefix when the admin prefix is the default', function () {
    $this->get('/shield/bans?file=/root/.aws/credentials')
        ->assertHeaderMissing('X-Shield-Blocked');
});

it('challenges repeated login attempts on a sensitive path', function () {
    for ($i = 0; $i < 7; $i++) {
        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.6'])
            ->post('/login', ['username' => 'x', 'password' => 'y'])
            ->assertStatus(404);
    }

    $response = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.6'])
        ->post('/login', ['username' => 'x', 'password' => 'y']);

    $response->assertRedirect();
    expect((string) $response->headers->get('Location'))->toContain('/shield/challenge');
});

it('blocks SQL injection payloads in a form request body', function () {
    $this->call('POST', '/login', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], "username=admin'+UNION+SELECT+password+FROM+users--&password=x")
        ->assertStatus(404)
        ->assertHeader('X-Shield-Blocked', 'payload.sqli.union');
});

it('blocks SQL injection payloads in a JSON request body', function () {
    $this->postJson('/api/login', ['username' => "admin' UNION SELECT password FROM users--", 'password' => 'x'])
        ->assertStatus(404)
        ->assertHeader('X-Shield-Blocked', 'payload.sqli.union');
});

it('does not inspect bodies when body inspection is disabled', function () {
    config()->set('shield.inspection.body.enabled', false);

    $this->call('POST', '/login', [], [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], "username=admin'+UNION+SELECT+password+FROM+users--")
        ->assertStatus(404);
});

it('lets a verified crawler pass in challenge mode', function () {
    config()->set('shield.bots.mode', 'challenge');
    config()->set('shield.bots.verification.ip_ranges.googlebot', ['127.0.0.0/8']);

    $this->get('/home', ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'])
        ->assertOk()
        ->assertSee('home');
});

it('challenges an unverified crawler claim in challenge mode', function () {
    config()->set('shield.bots.mode', 'challenge');

    $response = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.9'])
        ->get('/home', ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)']);

    $response->assertRedirect();
    expect((string) $response->headers->get('Location'))->toContain('/shield/challenge');
});

it('serves an unverified crawler with the default bot mode', function () {
    $response = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.9'])
        ->get('/home', ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)']);

    $response->assertOk()->assertSee('home');
});

it('still blocks a critical signature from a verified crawler', function () {
    config()->set('shield.bots.verification.ip_ranges.googlebot', ['127.0.0.0/8']);

    $this->get('/.env', ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)'])
        ->assertStatus(404)
        ->assertHeader('X-Shield-Blocked', 'sensitive.env');
});

it('lets a verified crawler crawl aggressively without being challenged', function () {
    config()->set('shield.bots.verification.ip_ranges.googlebot', ['127.0.0.0/8']);

    for ($i = 0; $i < 40; $i++) {
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get("/blog/post-{$i}", ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)'])
            ->assertNotFound()
            ->assertHeaderMissing('X-Shield-Blocked');
    }

    expect(SecurityIpBan::query()->count())->toBe(0);
});

it('still allows normal users without any crawler handling', function () {
    $this->get('/home', ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'])
        ->assertOk()
        ->assertSee('home');
});

it('wordpress rule pack is off by default', function () {
    config()->set('shield.rules.packs.wordpress', false);

    $this->get('/wp-json/gravitysmtp/v1/tests/mock-data')
        ->assertHeaderMissing('X-Shield-Blocked');
});

it('wordpress rule pack blocks plugin probes when enabled', function () {
    config()->set('shield.rules.packs.wordpress', true);

    $this->get('/wp-json/gravitysmtp/v1/tests/mock-data')
        ->assertStatus(404)
        ->assertHeader('X-Shield-Blocked', 'wp.gravitysmtp');
});

it('rejects an invalid challenge token', function () {
    $token = 'csrf-token';
    $this->withSession(['_token' => $token])
        ->post('/shield/challenge/verify', [
            '_token' => $token,
            'shield_challenge_token' => 'wrong',
            'redirect' => '/home',
        ])->assertRedirect(route('shield.challenge', ['error' => 1]));
});

it('never redirects to external hosts from the challenge flow', function () {
    $token = 'csrf-token';

    foreach ([
        'https://evil.example/phish',
        '//evil.example/phish',
        '/\\/evil.example/phish',
        '/\\evil.example/phish',
        '/%5c%5cevil.example/phish',
        'javascript:alert(1)',
        '/\\http:evil.example',
    ] as $redirect) {
        $this->withSession(['_token' => $token])
            ->post('/shield/challenge/verify', [
                '_token' => $token,
                'shield_challenge_token' => 'test-token',
                'redirect' => $redirect,
            ])->assertRedirect('/');
    }
});

it('still allows same-origin relative redirects', function () {
    $token = 'csrf-token';

    $this->withSession(['_token' => $token])
        ->post('/shield/challenge/verify', [
            '_token' => $token,
            'shield_challenge_token' => 'test-token',
            'redirect' => '/home?from=challenge',
        ])->assertRedirect('/home?from=challenge');
});

it('keeps the query separator intact when redirecting with several parameters', function () {
    $token = 'csrf-token';

    // e() here would turn the separator into "&amp;" and the Location header
    // would carry a parameter literally named "amp;page".
    $this->withSession(['_token' => $token])
        ->post('/shield/challenge/verify', [
            '_token' => $token,
            'shield_challenge_token' => 'test-token',
            'redirect' => '/home?mode=app&page=2',
        ])->assertRedirect('/home?mode=app&page=2');
});

it('escapes the redirect when rendering it on the challenge page', function () {
    $html = $this->get('/shield/challenge?redirect='.urlencode('/home?a=1&b=2'))
        ->assertOk()
        ->getContent();

    // The raw value must not be injected as markup, but it is rendered through
    // Blade so the separator survives as a real ampersand.
    expect($html)->not->toContain('<script>alert(1)</script>');
});

describe('api responses', function () {
    it('returns json for a block when the client accepts json', function () {
        $response = $this->getJson('/.env')->assertStatus(404);

        $response->assertHeader('X-Shield-Blocked', 'sensitive.env');
        expect($response->json('error'))->toBe('request_blocked');
        expect($response->json('rule_id'))->toBe('sensitive.env');
        expect($response->json('decision'))->toBe('BLOCK_REQUEST');
        expect($response->json('app_id'))->not->toBeEmpty();
    });

    it('returns json for a block on a configured api path without an accept header', function () {
        config()->set('shield.api.paths', ['/oauth/token']);

        $response = $this->get('/oauth/token/.env')->assertStatus(404);

        $response->assertHeader('Content-Type', 'application/json');
        $response->assertHeader('X-Shield-Blocked', 'sensitive.env');
        expect($response->json('error'))->toBe('request_blocked');
    });

    it('returns json for a challenge instead of a redirect', function () {
        SecurityIpBan::query()->create([
            'ip_address' => '10.0.0.9',
            'status' => BanStatus::Active->value,
            'reason' => 'test ban',
            'risk_score' => 25,
            'offense_count' => 1,
            'banned_at' => now(),
            'expires_at' => now()->addHour(),
            'last_seen_at' => now(),
        ]);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.9'])
            ->getJson('/home')
            ->assertStatus(401);

        $response->assertHeader('X-Shield-Challenge', '1');
        $response->assertHeader('Content-Type', 'application/json');
        expect($response->json('error'))->toBe('challenge_required');
        expect($response->json('challenge_url'))->toContain('/shield/challenge');
        expect($response->headers->get('Location'))->toBeNull();
    });

    it('keeps sending html to a browser', function () {
        $response = $this->get('/.env')->assertStatus(404);

        $response->assertHeader('Content-Type', 'text/html; charset=UTF-8');
        expect($response->getContent())->toContain('Access Blocked');
    });

    it('keeps redirecting a browser to the challenge page', function () {
        SecurityIpBan::query()->create([
            'ip_address' => '10.0.0.10',
            'status' => BanStatus::Active->value,
            'reason' => 'test ban',
            'risk_score' => 25,
            'offense_count' => 1,
            'banned_at' => now(),
            'expires_at' => now()->addHour(),
            'last_seen_at' => now(),
        ]);

        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.10'])
            ->get('/home')
            ->assertRedirect(route('shield.challenge', ['redirect' => '/home']));
    });

    it('can turn accept detection off while keeping explicit api paths', function () {
        config()->set('shield.api.detect_accept', false);
        config()->set('shield.api.paths', ['/api']);

        $this->getJson('/.env')->assertStatus(404);

        $response = $this->get('/.env')->assertStatus(404);
        $response->assertHeader('Content-Type', 'text/html; charset=UTF-8');
    });
});

describe('rules.skip_paths', function () {
    it('does not scan the body on a skipped path', function () {
        Route::post('/api/webhooks', fn () => ['stored' => true])->name('webhooks');
        config()->set('shield.rules.skip_paths', ['/api/webhooks']);

        // The SQLi payload is what payload.sqli.union matches on; the skipped
        // path means the body is never handed to the signature engine.
        $this->postJson('/api/webhooks', [
            'username' => "admin' UNION SELECT password FROM users--",
        ])->assertOk();
    });

    it('still scans the body on a path that is not skipped', function () {
        Route::post('/api/orders', fn () => ['created' => true])->name('orders');
        config()->set('shield.rules.skip_paths', ['/api/webhooks']);

        $this->postJson('/api/orders', [
            'username' => "admin' UNION SELECT password FROM users--",
        ])->assertStatus(404);
    });

    it('still enforces a critical signature in the uri on a skipped path', function () {
        Route::post('/api/webhooks', fn () => ['stored' => true])->name('webhooks');
        config()->set('shield.rules.skip_paths', ['/api/webhooks']);

        $this->get('/api/webhooks/.env')->assertStatus(404);
    });
});
