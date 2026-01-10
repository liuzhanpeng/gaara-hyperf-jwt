<?php

declare(strict_types=1);

use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManager;
use GaaraHyperf\Token\TokenInterface;
use Psr\SimpleCache\CacheInterface;

describe('RefreshTokenManager', function () {
    $createToken = function (string $userIdentifier = 'user-1'): TokenInterface {
        $token = \Mockery::mock(TokenInterface::class);
        $token->shouldReceive('getGuardName')->andReturn('guard');
        $token->shouldReceive('getUserIdentifier')->andReturn($userIdentifier);

        return $token;
    };

    it('issues and resolves refresh tokens', function () use ($createToken) {
        $stored = [];
        $cache = \Mockery::mock(CacheInterface::class);
        $cache->shouldReceive('set')->andReturnUsing(function ($key, $value) use (&$stored) {
            $stored[$key] = $value;
            return true;
        });
        $cache->shouldReceive('get')->andReturnUsing(function ($key) use (&$stored) {
            return $stored[$key] ?? null;
        });

        $manager = new RefreshTokenManager($cache, 'rt', 600, false, 32);
        $token = $createToken();

        $refreshToken = $manager->issue($token);

        expect(strlen($refreshToken->token()))->toBe(32);
        expect($refreshToken->expiresIn())->toBe(600);
        expect($manager->resolve($refreshToken->token()))->toBe($token);
    });

    it('enforces single-session by replacing previous tokens', function () use ($createToken) {
        $stored = [];
        $cache = \Mockery::mock(CacheInterface::class);
        $cache->shouldReceive('set')->andReturnUsing(function ($key, $value) use (&$stored) {
            $stored[$key] = $value;
            return true;
        });
        $cache->shouldReceive('get')->andReturnUsing(function ($key) use (&$stored) {
            return $stored[$key] ?? null;
        });
        $cache->shouldReceive('delete')->andReturnUsing(function ($key) use (&$stored) {
            unset($stored[$key]);
            return true;
        });

        $manager = new RefreshTokenManager($cache, 'rt', 600, true, 32);
        $token = $createToken();

        $first = $manager->issue($token);
        $second = $manager->issue($token);

        expect($manager->resolve($first->token()))->toBeNull();
        expect($manager->resolve($second->token()))->toBe($token);
        expect($cache->get('rt:user:user-1'))->toBe($second->token());
    });

    it('revokes refresh tokens and clears user mapping when single-session', function () use ($createToken) {
        $stored = [];
        $cache = \Mockery::mock(CacheInterface::class);
        $cache->shouldReceive('set')->andReturnUsing(function ($key, $value) use (&$stored) {
            $stored[$key] = $value;
            return true;
        });
        $cache->shouldReceive('get')->andReturnUsing(function ($key) use (&$stored) {
            return $stored[$key] ?? null;
        });
        $cache->shouldReceive('delete')->andReturnUsing(function ($key) use (&$stored) {
            unset($stored[$key]);
            return true;
        });

        $manager = new RefreshTokenManager($cache, 'rt', 600, true, 32);
        $token = $createToken();

        $issued = $manager->issue($token);
        $manager->revoke($issued->token());

        expect($manager->resolve($issued->token()))->toBeNull();
        expect($cache->get('rt:user:user-1'))->toBeNull();
    });

    it('validates refresh token length requirement', function () {
        $cache = \Mockery::mock(CacheInterface::class);
        new RefreshTokenManager($cache, 'rt', 600, false, 15);
    })->throws(\InvalidArgumentException::class, 'even number and not less than 16');
});
