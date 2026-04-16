<?php

declare(strict_types=1);

use GaaraHyperf\Exception\InvalidAccessTokenException;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuer;
use GaaraHyperf\JWT\JWTUser;

it('issues and resolves an access token with custom claims', function (): void {
    $issuer = new AccessTokenIssuer(
        algo: 'HS512',
        secretKey: str_repeat('a', 64),
        publicKey: null,
        passphrase: '',
        ttl: 600,
        leeway: 0,
        iss: 'gaara-test',
        aud: 'gaara-api',
    );

    $accessToken = $issuer->issue(makeTokenMock('user-123'), [
        'role' => 'admin',
        'tenant' => 'acme',
    ]);

    $user = $issuer->resolve($accessToken->token());

    expect($accessToken->token())->not->toBe('')
        ->and($accessToken->expiresIn())->toBe(600)
        ->and($user)->toBeInstanceOf(JWTUser::class)
        ->and($user->getIdentifier())->toBe('user-123')
        ->and($user->getAttributes())->toBe([
            'role' => 'admin',
            'tenant' => 'acme',
        ]);
});

it('rejects malformed access token strings', function (): void {
    $issuer = new AccessTokenIssuer(
        algo: 'HS512',
        secretKey: str_repeat('a', 64),
        publicKey: null,
        passphrase: '',
        ttl: 600,
        leeway: 0,
        iss: 'gaara-test',
        aud: 'gaara-api',
    );

    expect(fn () => $issuer->resolve('not-a-jwt'))
        ->toThrow(InvalidAccessTokenException::class, 'Failed to parse access token');
});

it('rejects tokens signed with another secret', function (): void {
    $issuer = new AccessTokenIssuer(
        algo: 'HS512',
        secretKey: str_repeat('a', 64),
        publicKey: null,
        passphrase: '',
        ttl: 600,
        leeway: 0,
        iss: 'gaara-test',
        aud: 'gaara-api',
    );

    $otherIssuer = new AccessTokenIssuer(
        algo: 'HS512',
        secretKey: str_repeat('b', 64),
        publicKey: null,
        passphrase: '',
        ttl: 600,
        leeway: 0,
        iss: 'gaara-test',
        aud: 'gaara-api',
    );

    $accessToken = $issuer->issue(makeTokenMock('user-123'));

    expect(fn () => $otherIssuer->resolve($accessToken->token()))
        ->toThrow(InvalidAccessTokenException::class, 'Invalid access token signature');
});

it('validates the secret key length for the selected algorithm', function (): void {
    expect(fn () => new AccessTokenIssuer(
        algo: 'HS512',
        secretKey: str_repeat('x', 10),
        publicKey: null,
        passphrase: '',
        ttl: 600,
        leeway: 0,
        iss: 'gaara-test',
        aud: 'gaara-api',
    ))->toThrow(InvalidArgumentException::class, 'at least 64 bytes long');
});

it('requires a public key for asymmetric algorithms', function (): void {
    expect(fn () => new AccessTokenIssuer(
        algo: 'RS256',
        secretKey: str_repeat('r', 256),
        publicKey: null,
        passphrase: '',
        ttl: 600,
        leeway: 0,
        iss: 'gaara-test',
        aud: 'gaara-api',
    ))->toThrow(InvalidArgumentException::class, 'Missing public key for asymmetric algorithm');
});
