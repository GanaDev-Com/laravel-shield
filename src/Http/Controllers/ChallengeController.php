<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Http\Controllers;

use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

final class ChallengeController
{
    public function __construct(
        private readonly ChallengeDriverInterface $driver,
        private readonly ShieldEngine $engine,
        private readonly ShieldConfig $config,
        private readonly ResponseFactory $response,
        private readonly ViewFactory $views,
    ) {}

    public function show(Request $request): Response
    {
        $payload = $this->driver->render($this->context($request));

        $data = [
            'driver' => $payload->driver,
            'siteKey' => $payload->siteKey,
            'testToken' => (string) ($payload->data['test_token'] ?? ''),
            'csrfToken' => $this->sessionToken($request),
            'redirect' => $this->safeRedirect($request),
            'error' => $request->query->getBoolean('error', false),
            'branding' => $this->config->branding,
        ];

        $view = $this->config->challengeView;
        if ($this->views->exists($view)) {
            $html = $this->views->make($view, $data)->render();
        } else {
            /** @var view-string $fallback */
            $fallback = 'shield::challenge';
            $html = $this->views->make($fallback, $data)->render();
        }

        return $this->response->make($html, 200, ['Cache-Control' => 'no-store']);
    }

    public function verify(Request $request): RedirectResponse
    {
        $context = $this->context($request);
        $token = (string) $request->input('shield_challenge_token', '');

        $result = $this->driver->verify($token, $context);

        if (! $result->passed) {
            return $this->response->redirectToRoute('shield.challenge', ['error' => 1]);
        }

        $this->engine->markChallengePassed($context->ip);
        $cookie = $this->engine->issueTrustedCookie($context);

        $response = $this->response->redirectTo($this->safeRedirect($request));

        if ($cookie !== '') {
            $response->withCookie(
                cookie($this->engine->trustedCookieName(), $cookie, $this->config->trustedTtlMinutes, '/', null, true, true, false, 'Lax'),
            );
        }

        return $response;
    }

    private function context(Request $request): RequestContext
    {
        return RequestContext::create(
            rawUri: (string) $request->getRequestUri(),
            method: (string) $request->method(),
            host: (string) $request->getHost(),
            ip: (string) $request->ip(),
            headersSubset: ['user-agent' => (string) $request->userAgent()],
        );
    }

    private function sessionToken(Request $request): string
    {
        if (! $request->hasSession()) {
            return '';
        }

        return (string) $request->session()->token();
    }

    private function safeRedirect(Request $request): string
    {
        $redirect = (string) $request->input('redirect', '/');

        if ($redirect === '' || ! str_starts_with($redirect, '/')) {
            return '/';
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $redirect) === 1) {
            return '/';
        }

        // Normalize backslash (browsers treat \ as /) and %5c / %2f on a copy
        // to catch protocol-relative and scheme injections.
        $normalized = strtolower(str_replace(
            ['\\', '%5c', '%2f'],
            ['/', '/', '/'],
            $redirect,
        ));

        if (str_starts_with($normalized, '//')) {
            return '/';
        }

        if (preg_match('#^/[a-z][a-z0-9+.-]*:#', $normalized) === 1) {
            return '/';
        }

        // Return the path unescaped. e() would turn the query separator into
        // "&amp;", which then lands verbatim in the Location header and breaks
        // every redirect target that carries more than one parameter. All
        // rendering goes through Blade's {{ }} so output stays escaped there.
        return $redirect;
    }
}
