<?php

declare(strict_types=1);

use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerInterface;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerResolver;

it('caches resolved refresh token issuers', function (): void {
    $refreshIssuer = Mockery::mock(RefreshTokenIssuerInterface::class);
    $calls = 0;

    $resolver = new RefreshTokenIssuerResolver([
        'default' => function () use (&$calls, $refreshIssuer) {
            ++$calls;
            return $refreshIssuer;
        },
    ]);

    expect($resolver->resolve())->toBe($refreshIssuer)
        ->and($resolver->resolve())->toBe($refreshIssuer)
        ->and($calls)->toBe(1);
});

it('fails when resolving an undefined refresh token issuer', function (): void {
    expect(fn () => (new RefreshTokenIssuerResolver([]))->resolve('missing'))
        ->toThrow(InvalidArgumentException::class, 'RefreshToken Issuer "missing" is not defined');
});
