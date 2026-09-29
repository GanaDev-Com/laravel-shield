<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Challenge;

use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Challenge\ChallengePayload;
use Ganadev\Shield\Core\Challenge\ChallengeResult;
use Ganadev\Shield\Core\Context\RequestContext;

/**
 * Deterministic driver for automated tests and local development. Passes when
 * the submitted token equals "test-token".
 */
final class NullTestDriver implements ChallengeDriverInterface
{
    public const TEST_TOKEN = 'test-token';

    public function name(): string
    {
        return 'null';
    }

    public function render(RequestContext $context): ChallengePayload
    {
        return new ChallengePayload(
            driver: 'null',
            siteKey: 'test',
            action: 'shield_challenge',
            data: ['test_token' => self::TEST_TOKEN],
        );
    }

    public function verify(string $token, RequestContext $context): ChallengeResult
    {
        return $token === self::TEST_TOKEN
            ? ChallengeResult::success('null')
            : ChallengeResult::failure('null', 'invalid_token');
    }
}
