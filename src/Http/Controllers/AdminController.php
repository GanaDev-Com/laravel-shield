<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Http\Controllers;

use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Laravel\Repositories\EloquentBanRepository;
use Ganadev\Shield\Laravel\Repositories\EloquentEventRepository;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Optional management surface. Every route must be protected by the
 * configurable admin middleware + an authorization hook (enforced here).
 */
final class AdminController
{
    public function __construct(
        private readonly EloquentBanRepository $bans,
        private readonly EloquentEventRepository $events,
        private readonly RuleRepository $rules,
        private readonly DatabaseManager $db,
        private readonly ResponseFactory $response,
        private readonly ShieldConfig $config,
    ) {}

    public function bans(Request $request): JsonResponse
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        return $this->response->json(
            $this->bans->paginate($request->only(['ip', 'status']), $this->perPage($request)),
        );
    }

    public function banDetail(string $id): JsonResponse
    {
        if (! $this->authorized(request())) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->response->json(['error' => 'not_found'], 404);
        }

        return $this->response->json(['ban' => $ban]);
    }

    public function release(Request $request, string $id): JsonResponse
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->response->json(['error' => 'not_found'], 404);
        }

        $released = $this->bans->release(
            $ban,
            (string) $request->input('reason', 'manual_release'),
            $this->actor($request),
        );

        return $this->response->json(['ban' => $released]);
    }

    public function extend(Request $request, string $id): JsonResponse
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->response->json(['error' => 'not_found'], 404);
        }

        $minutes = max(1, (int) $request->input('minutes', 60));
        $expires = \DateTimeImmutable::createFromInterface($ban->expiresAt ?? now());

        $extended = $this->bans->extend(
            $ban,
            // add() is used instead of modify() because modify() is declared as
            // possibly returning false, which would need a version dependent guard.
            $expires->add(new \DateInterval('PT'.$minutes.'M')),
            $this->actor($request),
        );

        return $this->response->json(['ban' => $extended]);
    }

    public function events(Request $request): JsonResponse
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        return $this->response->json(
            $this->events->paginate($request->only(['ip', 'host', 'rule_id', 'severity', 'decision']), $this->perPage($request)),
        );
    }

    public function rules(Request $request): JsonResponse
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $rules = [];
        foreach ($this->rules->all() as $rule) {
            $rules[] = [
                'id' => $rule->id,
                'category' => $rule->category,
                'matcher' => $rule->matcher->value,
                'severity' => $rule->severity->value,
                'score' => $rule->score,
                'immediate_ban' => $rule->immediateBan,
                'enabled' => $rule->enabled,
            ];
        }

        return $this->response->json(['version' => '1.0.0', 'count' => count($rules), 'rules' => $rules]);
    }

    public function health(Request $request): JsonResponse
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $dbOk = true;
        $cacheOk = true;
        $exception = null;

        try {
            $this->db->getPdo();
        } catch (\Throwable $e) {
            $dbOk = false;
            $exception = $e;
        }

        try {
            app('cache')->store()->get('shield:health:probe');
        } catch (\Throwable) {
            $cacheOk = false;
        }

        $proxyWarning = null;
        $forwarded = (string) $request->header('X-Forwarded-For', '') !== ''
            || (string) $request->header('Forwarded', '') !== '';
        if ($forwarded && $request->getTrustedProxies() === []) {
            $proxyWarning = 'Forwarded headers present but trusted proxies are not configured.';
        }

        return $this->response->json([
            'healthy' => $dbOk && $cacheOk,
            'database' => $dbOk,
            'cache' => $cacheOk,
            'engine' => true,
            'trusted_proxy_warning' => $proxyWarning,
            'error' => $exception?->getMessage(),
        ], $dbOk && $cacheOk ? 200 : 503);
    }

    private function perPage(Request $request): int
    {
        return min(max((int) $request->input('per_page', 50), 1), 200);
    }

    private function authorized(Request $request): bool
    {
        if ($this->config->adminAuthorize === '') {
            return true;
        }

        $user = $request->user();

        return $user !== null && $user->can($this->config->adminAuthorize);
    }

    private function denied(): JsonResponse
    {
        return $this->response->json(['error' => 'forbidden'], 403);
    }

    private function actor(Request $request): ?string
    {
        $user = $request->user();

        return $user !== null ? (string) $user->getAuthIdentifier() : null;
    }
}
