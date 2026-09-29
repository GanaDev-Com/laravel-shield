<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Trust;

use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;
use Illuminate\Contracts\Encryption\Encrypter;

/**
 * Signed/encrypted, HttpOnly-ready trusted cookie bound to a light user-agent
 * hash plus a coarse IP prefix. It is never an authorization token and never
 * bypasses critical signatures (enforced by the decision engine).
 */
final class LaravelTrustedCookie implements TrustedCookieInterface
{
    public function __construct(
        private readonly Encrypter $encrypter,
    ) {}

    public function name(): string
    {
        return 'shield_trusted';
    }

    public function issue(RequestContext $context, int $ttlMinutes): string
    {
        $payload = [
            'exp' => time() + ($ttlMinutes * 60),
            'ua' => $this->uaHash($context->userAgent()),
            'ip' => $this->coarsePrefix($context->ip),
        ];

        return $this->encrypter->encrypt($payload);
    }

    public function validate(string $cookieValue, RequestContext $context): bool
    {
        try {
            $payload = $this->encrypter->decrypt($cookieValue);
        } catch (\Throwable) {
            return false;
        }

        if (! is_array($payload)) {
            return false;
        }

        $exp = (int) ($payload['exp'] ?? 0);
        if ($exp <= time()) {
            return false;
        }

        if (($payload['ua'] ?? '') !== $this->uaHash($context->userAgent())) {
            return false;
        }

        if (($payload['ip'] ?? '') !== $this->coarsePrefix($context->ip)) {
            return false;
        }

        return true;
    }

    private function uaHash(string $userAgent): string
    {
        return hash('sha256', strtolower(trim($userAgent)));
    }

    private function coarsePrefix(string $ip): string
    {
        if (str_contains($ip, ':')) {
            $parts = explode(':', $ip);

            return implode(':', array_slice($parts, 0, 4));
        }

        $parts = explode('.', $ip);

        return implode('.', array_slice($parts, 0, 3));
    }
}
