<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManager;
use GaaraHyperf\Token\TokenInterface;

function generateEcKeyPair(): array
{
    $config = [
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ];

    $res = openssl_pkey_new($config);
    openssl_pkey_export($res, $privateKey);
    $details = openssl_pkey_get_details($res);

    return [$privateKey, $details['key']];
}

function generateRsaKeyPair(): array
{
    $config = [
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    $res = openssl_pkey_new($config);
    openssl_pkey_export($res, $privateKey);
    $details = openssl_pkey_get_details($res);

    return [$privateKey, $details['key']];
}

describe('AccessTokenManager', function () {
    $secret = str_repeat('a', 64);
    [$esPrivateKey, $esPublicKey] = generateEcKeyPair();
    [$rsaPrivateKey, $rsaPublicKey] = generateRsaKeyPair();

    $createToken = function (string $userIdentifier = 'user-123'): TokenInterface {
        $token = \Mockery::mock(TokenInterface::class);
        $token->shouldReceive('getGuardName')->andReturn('guard');
        $token->shouldReceive('getUserIdentifier')->andReturn($userIdentifier);

        return $token;
    };

    it('issues and parses a valid token', function () use ($secret, $createToken) {
        $manager = new AccessTokenManager('HS256', $secret, null, '', 600, null, 'issuer', 'audience');
        $token = $createToken();

        $accessToken = $manager->issue($token);
        expect($accessToken->token())->not->toBeEmpty();
        expect($accessToken->expiresIn())->toBe(600);

        $user = $manager->parse($accessToken->token());

        expect($user->getIdentifier())->toBe('user-123');
        expect($user->getAttributes())->toBe([]);
    });

    it('rejects malformed token strings', function () use ($secret) {
        $manager = new AccessTokenManager('HS256', $secret, null, '', 600, null, 'issuer', 'audience');

        $manager->parse('not-a-jwt');
    })->throws(\RuntimeException::class, 'Failed to parse access token');

    it('rejects expired tokens', function () use ($secret, $createToken) {
        $manager = new AccessTokenManager('HS256', $secret, null, '', -10, null, 'issuer', 'audience');
        $token = $createToken();

        $accessToken = $manager->issue($token);

        $manager->parse($accessToken->token());
    })->throws(\RuntimeException::class, 'Access token is expired or not yet valid');

    it('rejects tokens with invalid signature', function () use ($secret, $createToken) {
        $issuer = 'issuer';
        $audience = 'audience';
        $token = $createToken();

        $issuerManager = new AccessTokenManager('HS256', $secret, null, '', 600, null, $issuer, $audience);
        $accessToken = $issuerManager->issue($token);

        $parserManager = new AccessTokenManager('HS256', str_repeat('b', 64), null, '', 600, null, $issuer, $audience);
        $parserManager->parse($accessToken->token());
    })->throws(\RuntimeException::class, 'Invalid access token signature');

    it('rejects tokens with wrong issuer', function () use ($secret, $createToken) {
        $token = $createToken();

        $issuerManager = new AccessTokenManager('HS256', $secret, null, '', 600, null, 'issuer-a', 'audience');
        $accessToken = $issuerManager->issue($token);

        $parserManager = new AccessTokenManager('HS256', $secret, null, '', 600, null, 'issuer-b', 'audience');
        $parserManager->parse($accessToken->token());
    })->throws(\RuntimeException::class, 'Invalid access token issuer');

    it('rejects tokens with wrong audience', function () use ($secret, $createToken) {
        $token = $createToken();

        $issuerManager = new AccessTokenManager('HS256', $secret, null, '', 600, null, 'issuer', 'audience-a');
        $accessToken = $issuerManager->issue($token);

        $parserManager = new AccessTokenManager('HS256', $secret, null, '', 600, null, 'issuer', 'audience-b');
        $parserManager->parse($accessToken->token());
    })->throws(\RuntimeException::class, 'Access token not permitted for this audience');

    it('issues and parses ES256 tokens with asymmetric keys', function () use ($esPrivateKey, $esPublicKey, $createToken) {
        $manager = new AccessTokenManager('ES256', $esPrivateKey, $esPublicKey, '', 600, null, 'issuer', 'audience');
        $token = $createToken();

        $accessToken = $manager->issue($token);
        $user = $manager->parse($accessToken->token());

        expect($user->getIdentifier())->toBe('user-123');
    });

    it('issues and parses RS256 tokens with asymmetric keys', function () use ($rsaPrivateKey, $rsaPublicKey, $createToken) {
        $manager = new AccessTokenManager('RS256', $rsaPrivateKey, $rsaPublicKey, '', 600, null, 'issuer', 'audience');
        $token = $createToken();

        $accessToken = $manager->issue($token);
        $user = $manager->parse($accessToken->token());

        expect($user->getIdentifier())->toBe('user-123');
    });
});
