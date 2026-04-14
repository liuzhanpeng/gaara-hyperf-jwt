<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\JWT\RefreshToken;

describe('Value objects', function () {
    it('returns access token values', function () {
        $accessToken = new AccessToken('access', 600);

        expect($accessToken->token())->toBe('access');
        expect($accessToken->expiresIn())->toBe(600);
    });

    it('returns refresh token values', function () {
        $refreshToken = new RefreshToken('refresh', 3600);

        expect($refreshToken->token())->toBe('refresh');
        expect($refreshToken->expiresIn())->toBe(3600);
    });

    it('returns jwt user values', function () {
        $user = new JWTUser('user-1', ['role' => 'admin']);

        expect($user->getIdentifier())->toBe('user-1');
        expect($user->getAttributes())->toBe(['role' => 'admin']);
    });
});
