<?php

declare(strict_types=1);

use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerResolver;

it('caches resolved jwt managers', function (): void {
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $calls = 0;

    $resolver = new JWTokenManagerResolver([
        'default' => function () use (&$calls, $jwtManager) {
            ++$calls;
            return $jwtManager;
        },
    ]);

    expect($resolver->resolve())->toBe($jwtManager)
        ->and($resolver->resolve())->toBe($jwtManager)
        ->and($calls)->toBe(1);
});

it('fails when resolving an undefined jwt manager', function (): void {
    expect(fn () => (new JWTokenManagerResolver([]))->resolve('missing'))
        ->toThrow(InvalidArgumentException::class, 'JWTokenManager "missing" is not defined');
});
