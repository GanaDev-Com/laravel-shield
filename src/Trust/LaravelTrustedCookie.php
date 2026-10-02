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
    private bool $warnedAboutPosition = false;

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
        if ($this->looksAlreadyDecrypted($cookieValue)) {
            // The firewall is documented to run as global middleware, which
            // means before the web group's EncryptCookies. If it is ever moved
            // into that group, Laravel hands the cookie over already decrypted
            // and this decrypt() call would fail for every user, so trusted
            // traffic would be challenged in a loop. Report the misplacement
            // once instead of letting it look like random cookie corruption.
            $this->warnAboutMiddlewarePosition();

            return false;
        }

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

    /**
     * An encrypted payload is an opaque base64/serialized blob, never JSON. A
     * JSON-looking value can therefore only come from Laravel's cookie
     * decryption already having run upstream.
     */
    private function looksAlreadyDecrypted(string $cookieValue): bool
    {
        $trimmed = ltrim($cookieValue);

        return $trimmed !== '' && ($trimmed[0] === '{' || $trimmed[0] === '[');
    }

    private function warnAboutMiddlewarePosition(): void
    {
        if ($this->warnedAboutPosition) {
            return;
        }

        $this->warnedAboutPosition = true;

        if (! function_exists('logger')) {
            return;
        }

        logger()->warning('Ganadev Shield: cookie trusted diterima dalam bentuk yang sudah ter-decrypt. '
            .'Middleware shield.firewall kemungkinan sudah dipindahkan ke dalam group "web" sehingga '
            .'EncryptCookies berjalan lebih dulu. Kembalikan middleware ke posisi global (append), '
            .'agar Shield membaca cookie terenkripsi itu sendiri.');
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
