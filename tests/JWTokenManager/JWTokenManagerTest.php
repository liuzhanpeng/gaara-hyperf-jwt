<?php

declare(strict_types=1);

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\AccessTokenIssuer\AccessTokenIssuerInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManager;
use GaaraHyperf\JWT\JWTokenManager\JWTokenResponder\JWTokenResponderInterface;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\JWT\RefreshTokenIssuer\RefreshTokenIssuerInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;

it('requires refresh token configuration when the feature is enabled', function (): void {
    $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
    $accessIssuer = Mockery::mock(AccessTokenIssuerInterface::class);
    $responder = Mockery::mock(JWTokenResponderInterface::class);

    expect(fn () => new JWTokenManager($accessExtractor, $accessIssuer, $responder, true, ''))
        ->toThrow(InvalidArgumentException::class, 'Refresh path must be provided');

    expect(fn () => new JWTokenManager($accessExtractor, $accessIssuer, $responder, true, '/refresh'))
        ->toThrow(InvalidArgumentException::class, 'Refresh token extractor must be provided');
});

it('issues access and refresh tokens through the configured collaborators', function (): void {
    $requestToken = makeTokenMock('user-1');
    $accessToken = new AccessToken('access-123', 600);
    $refreshToken = new RefreshToken('refresh-456', 3600);
    $response = Mockery::mock(PsrResponseInterface::class);

    $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
    $accessIssuer = Mockery::mock(AccessTokenIssuerInterface::class);
    $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
    $refreshIssuer = Mockery::mock(RefreshTokenIssuerInterface::class);
    $responder = Mockery::mock(JWTokenResponderInterface::class);

    $accessIssuer->shouldReceive('issue')->once()->with($requestToken, ['role' => 'admin'])->andReturn($accessToken);
    $refreshIssuer->shouldReceive('issue')->once()->with($requestToken)->andReturn($refreshToken);
    $responder->shouldReceive('respond')->once()->with($accessToken, $refreshToken)->andReturn($response);

    $manager = new JWTokenManager(
        accessTokenExtractor: $accessExtractor,
        accessTokenIssuer: $accessIssuer,
        responder: $responder,
        isRefreshTokenEnabled: true,
        refreshTokenPath: '/refresh',
        refreshTokenExtractor: $refreshExtractor,
        refreshTokenIssuer: $refreshIssuer,
    );

    expect($manager->issue($requestToken, ['role' => 'admin']))->toBe($response);
});

it('resolves access tokens from the request', function (): void {
    $request = makeRequest();
    $jwtUser = new JWTUser('user-1', ['role' => 'admin']);

    $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
    $accessIssuer = Mockery::mock(AccessTokenIssuerInterface::class);
    $responder = Mockery::mock(JWTokenResponderInterface::class);

    $accessExtractor->shouldReceive('extract')->once()->with($request)->andReturn('jwt-token');
    $accessIssuer->shouldReceive('resolve')->once()->with('jwt-token')->andReturn($jwtUser);

    $manager = new JWTokenManager($accessExtractor, $accessIssuer, $responder, false);

    expect($manager->resolveAccessToken($request))->toBe($jwtUser)
        ->and($manager->isRefreshTokenEnabled())->toBeFalse();
});

it('resolves and revokes refresh tokens when enabled', function (): void {
    $request = makeRequest('POST', '/refresh');
    $requestToken = makeTokenMock('user-1');

    $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
    $accessIssuer = Mockery::mock(AccessTokenIssuerInterface::class);
    $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
    $refreshIssuer = Mockery::mock(RefreshTokenIssuerInterface::class);
    $responder = Mockery::mock(JWTokenResponderInterface::class);

    $refreshExtractor->shouldReceive('extract')->twice()->with($request)->andReturn('refresh-456');
    $refreshIssuer->shouldReceive('resolve')->once()->with('refresh-456')->andReturn($requestToken);
    $refreshIssuer->shouldReceive('revoke')->once()->with('refresh-456');

    $manager = new JWTokenManager(
        accessTokenExtractor: $accessExtractor,
        accessTokenIssuer: $accessIssuer,
        responder: $responder,
        isRefreshTokenEnabled: true,
        refreshTokenPath: '/refresh',
        refreshTokenExtractor: $refreshExtractor,
        refreshTokenIssuer: $refreshIssuer,
    );

    expect($manager->refreshTokenPath())->toBe('/refresh')
        ->and($manager->resolveRefreshToken($request))->toBe($requestToken);

    $manager->revokeRefreshToken($request);
});
