<?php

declare(strict_types=1);

namespace Ganadev\Shield\Laravel\Tests\Feature;

/**
 * Replays the scanner corpus through the real HTTP stack (middleware + engine
 * + Eloquent persistence) to prove end-to-end behaviour.
 */
it('replays the scanner corpus end-to-end without banning normal traffic', function () {
    $corpus = json_decode((string) file_get_contents(__DIR__.'/../../fixtures/scanner-corpus.json'), true, 512, JSON_THROW_ON_ERROR);
    $normal = json_decode((string) file_get_contents(__DIR__.'/../../fixtures/normal-traffic.json'), true, 512, JSON_THROW_ON_ERROR);

    foreach ($normal['requests'] as $request) {
        $response = $this->get($request['uri']);

        expect($response->headers->has('X-Shield-Blocked'))->toBeFalse();
        expect(str_contains((string) $response->headers->get('Location', ''), '/shield/challenge'))->toBeFalse();
    }

    foreach ($corpus['scenarios'] as $index => $scenario) {
        $expected = $scenario['expected'];
        $ip = '10.'.($index + 1).'.0.1';
        $peak = 'allow';

        foreach ($scenario['requests'] as $requestData) {
            $headers = [];
            foreach ($requestData['headers'] ?? [] as $name => $value) {
                $headers[str_replace('_', '-', ucwords((string) $name, '_'))] = $value;
            }

            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->withHeaders($headers)
                ->get($requestData['uri']);

            $outcome = match (true) {
                $response->getStatusCode() === 404 && $response->headers->has('X-Shield-Blocked') => 'block',
                $response->getStatusCode() === 302 && str_contains((string) $response->headers->get('Location'), '/shield/challenge') => 'challenge',
                default => 'allow',
            };

            if ($outcome === 'block') {
                $peak = 'block';
                break;
            }
            if ($outcome === 'challenge' && $peak !== 'block') {
                $peak = 'challenge';
            }
        }

        $passed = match ($expected) {
            'block' => $peak === 'block',
            'challenge', 'ban' => $peak === 'challenge' || $peak === 'block',
            default => $peak === 'allow',
        };

        expect($passed)->toBeTrue($scenario['id'].' expected='.$expected.' got='.$peak);
    }
});
