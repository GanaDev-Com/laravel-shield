<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Middleware;

use Closure;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Engine\EngineResult;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Privacy\UriMasker;
use Ganadev\Shield\Laravel\Cache\LaravelCacheAdapter;
use Ganadev\Shield\Laravel\Events\ShieldBlocked;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * Laravel adapter middleware. Position it as early as possible (after trusted
 * proxy resolution) and before your application routes so critical requests are
 * blocked before any controller logic runs.
 */
final class SecurityFirewallMiddleware
{
    public function __construct(
        private readonly ShieldEngine $engine,
        private readonly ShieldConfig $config,
        private readonly LaravelCacheAdapter $cache,
        private readonly UrlGenerator $url,
        private readonly ViewFactory $views,
    ) {}

    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        if (! $this->config->enabled || $this->isShieldRoute($request)) {
            return $next($request);
        }

        $context = $this->buildContext($request);
        $counters = $this->readCounters($context);

        try {
            $cookie = $request->cookie($this->engine->trustedCookieName());
            $result = $this->engine->inspect($context, $counters, [
                'trusted_cookie' => is_string($cookie) ? $cookie : '',
            ]);
        } catch (\Throwable) {
            return $this->onInfrastructureFailure($request, $next);
        }

        if ($result->shouldBlock()) {
            event(new ShieldBlocked(
                ip: $context->ip,
                ruleId: $result->verdict->ruleId ?? 'unknown',
                reason: $result->verdict->reason,
                score: $result->score->total,
                uri: $this->maskUri($context->rawUri),
                method: $context->method,
            ));

            return $this->blockResponse($request, $result);
        }

        if ($result->shouldChallenge()) {
            return $this->challengeResponse($request);
        }

        $response = $next($request);

        if ($response->getStatusCode() === 404) {
            $this->countNotFound($context);
        }

        return $response;
    }

    private function buildContext(Request $request): RequestContext
    {
        $referer = $request->headers->get('referer');

        return RequestContext::create(
            rawUri: (string) $request->getRequestUri(),
            method: (string) $request->method(),
            host: (string) $request->getHost(),
            ip: (string) $request->ip(),
            headersSubset: [
                'user-agent' => (string) $request->userAgent(),
                'referer' => is_string($referer) ? $referer : '',
            ],
            body: $this->captureBody($request),
        );
    }

    /**
     * Reads the request body for signature matching only when body inspection
     * is enabled. Multipart uploads are skipped (never buffer file content);
     * the body is truncated to `inspection.body.max_bytes` and is never logged.
     * Form bodies are urldecoded so "+"-encoded spaces match payload rules.
     */
    private function captureBody(Request $request): string
    {
        if (! $this->config->bodyInspectionEnabled) {
            return '';
        }

        $contentType = strtolower((string) $request->headers->get('content-type', ''));
        if (str_starts_with($contentType, 'multipart/')) {
            return '';
        }

        $body = (string) $request->getContent();
        if (strlen($body) > $this->config->bodyInspectionMaxBytes) {
            $body = substr($body, 0, $this->config->bodyInspectionMaxBytes);
        }

        if (str_starts_with($contentType, 'application/x-www-form-urlencoded')) {
            $body = urldecode($body);
        }

        return $body;
    }

    private function readCounters(RequestContext $context): BehaviorCounters
    {
        try {
            $unique = $this->cache->increment(
                "counters:{$context->ip}:unique",
                $this->config->behaviorWindowSeconds,
            );
            $notFound = (int) $this->cache->get("counters:{$context->ip}:not_found");

            $pathKey = strtolower((string) preg_replace('#/{2,}#', '/', $context->rawPath));
            $pathCount = $this->cache->increment(
                'counters:'.$context->ip.':path:'.hash('sha256', $pathKey),
                $this->config->behaviorWindowSeconds,
            );
            $sensitive = $this->isSensitivePath($pathKey);
        } catch (\Throwable) {
            return new BehaviorCounters;
        }

        return new BehaviorCounters(
            uniqueUriCount: $unique,
            notFoundCount: $notFound,
            pathRequestCount: $pathCount,
            isSensitivePath: $sensitive,
        );
    }

    private function isSensitivePath(string $path): bool
    {
        foreach ($this->config->sensitivePaths as $sensitive) {
            if (str_starts_with($path, $sensitive)) {
                return true;
            }
        }

        return false;
    }

    private function countNotFound(RequestContext $context): void
    {
        try {
            $this->cache->increment(
                "counters:{$context->ip}:not_found",
                $this->config->behaviorWindowSeconds,
            );
        } catch (\Throwable) {
            // Counter loss must never break the request flow.
        }
    }

    /**
     * Event listener (alerting Slack/Telegram, log audit) menerima payload event
     * yang sama dengan event tersimpan, sehingga parameter query sensitif wajib
     * dimask di sini juga. Tanpa ini, token hanya aman di database tetapi bocor ke
     * channel notifikasi pihak ketiga.
     */
    private function maskUri(string $uri): string
    {
        return (new UriMasker)->mask($uri, $this->config->sensitiveQueryParameters);
    }

    private function blockResponse(Request $request, EngineResult $result): SymfonyResponse
    {
        $data = [
            'ruleId' => $result->verdict->ruleId ?? 'unknown',
            'appId' => $this->config->appId,
            'branding' => $this->config->branding,
        ];

        $view = $this->config->blockedView;
        if ($this->views->exists($view)) {
            $html = $this->views->make($view, $data)->render();
        } else {
            /** @var view-string $fallback */
            $fallback = 'shield::blocked';
            $html = $this->views->make($fallback, $data)->render();
        }

        $response = new Response(
            $html,
            $this->config->responseCode,
        );
        $response->headers->set('X-Shield-Blocked', $result->verdict->ruleId ?? 'shield');
        $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate');

        return $response;
    }

    private function challengeResponse(Request $request): SymfonyResponse
    {
        // Kirim path relatif (bukan URL absolut) karena ChallengeController
        // hanya menerima redirect same-origin yang diawali "/". getRequestUri()
        // menghasilkan "/home" atau "/home?page=2" tanpa host.
        return new RedirectResponse(
            $this->url->route('shield.challenge', ['redirect' => $request->getRequestUri()]),
        );
    }

    private function onInfrastructureFailure(Request $request, Closure $next): SymfonyResponse
    {
        if ($this->config->failMode === ShieldConfig::FAIL_CLOSED) {
            return new Response('Service unavailable.', 503);
        }

        return $next($request);
    }

    private function isShieldRoute(Request $request): bool
    {
        $path = $request->path();

        return str_starts_with($path, 'shield/') || $path === 'shield';
    }
}
