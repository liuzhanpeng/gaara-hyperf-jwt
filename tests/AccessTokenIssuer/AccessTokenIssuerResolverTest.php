<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerInterface;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerResolver;

it('caches resolved access token issuers', function (): void {
    $accessIssuer = Mockery::mock(AccessTokenIssuerInterface::class);
    $calls = 0;

    $resolver = new AccessTokenIssuerResolver([
        'default' => function () use (&$calls, $accessIssuer) {
            ++$calls;
            return $accessIssuer;
        },
    ]);

    expect($resolver->resolve())->toBe($accessIssuer)
        ->and($resolver->resolve())->toBe($accessIssuer)
        ->and($calls)->toBe(1);
});

it('fails when resolving an undefined access token issuer', function (): void {
    expect(fn () => (new AccessTokenIssuerResolver([]))->resolve('missing'))
        ->toThrow(InvalidArgumentException::class, 'AccessToken Issuer "missing" is not defined');
});
