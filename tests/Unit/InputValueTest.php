<?php

declare(strict_types=1);

use Ganadev\Shield\Laravel\Support\InputValue;

it('returns a trimmed non empty string unchanged', function () {
    expect((new InputValue)->string('1.2.3.4'))->toBe('1.2.3.4')
        ->and((new InputValue)->string('  /tmp/corpus.json  '))->toBe('/tmp/corpus.json');
});

it('rejects values that are not usable strings', function (mixed $value) {
    expect((new InputValue)->string($value))->toBeNull();
})->with([
    'empty string' => '',
    'whitespace only' => '   ',
    'null' => null,
    'array' => [['a', 'b']],
    'integer' => 42,
    'float' => 1.5,
    'boolean' => true,
]);
