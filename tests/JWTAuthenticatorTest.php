<?php

declare(strict_types=1);

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\Exception\InvalidCredentialsException;
use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerInterface;
use GaaraHyperf\JWT\JWTAuthenticator;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use GaaraHyperf\Passport\Passport;
use Psr\Http\Message\ResponseInterface;

describe('JWTAuthenticator', function () {
    it('supports access-token request', function () {
        $request = makeRequest('GET', '/api/profile');

        $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $accessExtractor->shouldReceive('extract')->once()->with($request)->andReturn('access-token');

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: $accessExtractor,
            refreshTokenEnabled: true,
            refreshTokenManager: Mockery::mock(RefreshTokenManagerInterface::class),
            refreshTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
        );

        expect($authenticator->supports($request))->toBeTrue();
    });

    it('supports refresh request when refresh is enabled', function () {
        $request = makeRequest('POST', '/api/refresh');

        $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $accessExtractor->shouldReceive('extract')->once()->andReturn(null);

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: $accessExtractor,
            refreshTokenEnabled: true,
            refreshTokenManager: Mockery::mock(RefreshTokenManagerInterface::class),
            refreshTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
        );

        expect($authenticator->supports($request))->toBeTrue();
    });

    it('does not support refresh request when refresh is disabled', function () {
        $request = makeRequest('POST', '/api/refresh');

        $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $accessExtractor->shouldReceive('extract')->once()->andReturn(null);

        $authenticator = new JWTAuthenticator(
            refreshPath: '',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: $accessExtractor,
            refreshTokenEnabled: false,
        );

        expect($authenticator->supports($request))->toBeFalse();
    });

    it('authenticates access token request', function () {
        $request = makeRequest('GET', '/api/profile');

        $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $accessExtractor->shouldReceive('extract')->once()->with($request)->andReturn('jwt-token');

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManager->shouldReceive('parse')->once()->with('jwt-token')->andReturn(new JWTUser('user-123', ['role' => 'admin']));

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: $accessManager,
            accessTokenExtractor: $accessExtractor,
            refreshTokenEnabled: true,
            refreshTokenManager: Mockery::mock(RefreshTokenManagerInterface::class),
            refreshTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
        );

        $passport = $authenticator->authenticate($request);

        expect($passport->getUserIdentifier())->toBe('user-123');
        expect($passport->getUser())->toBeInstanceOf(JWTUser::class);
    });

    it('authenticates refresh token request', function () {
        $request = makeRequest('POST', '/api/refresh');
        $token = makeTokenMock('user-234');

        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor->shouldReceive('extract')->once()->with($request)->andReturn('refresh-token');

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('resolve')->once()->with('refresh-token')->andReturn($token);

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
            refreshTokenEnabled: true,
            refreshTokenManager: $refreshManager,
            refreshTokenExtractor: $refreshExtractor,
        );

        $passport = $authenticator->authenticate($request);
        expect($passport->getUserIdentifier())->toBe('user-234');
    });

    it('throws when access token is missing', function () {
        $request = makeRequest('GET', '/api/profile');

        $accessExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $accessExtractor->shouldReceive('extract')->once()->with($request)->andReturn(null);

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: $accessExtractor,
            refreshTokenEnabled: true,
            refreshTokenManager: Mockery::mock(RefreshTokenManagerInterface::class),
            refreshTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
        );

        $authenticator->authenticate($request);
    })->throws(InvalidCredentialsException::class, 'No access token found in the request');

    it('throws when refresh token is missing', function () {
        $request = makeRequest('POST', '/api/refresh');

        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor->shouldReceive('extract')->once()->with($request)->andReturn(null);

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('resolve')->never();

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
            refreshTokenEnabled: true,
            refreshTokenManager: $refreshManager,
            refreshTokenExtractor: $refreshExtractor,
        );

        $authenticator->authenticate($request);
    })->throws(InvalidCredentialsException::class, 'No refresh token found in the request');

    it('throws when refresh token cannot be resolved', function () {
        $request = makeRequest('POST', '/api/refresh');

        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor->shouldReceive('extract')->once()->with($request)->andReturn('bad-token');

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('resolve')->once()->with('bad-token')->andReturn(null);

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
            refreshTokenEnabled: true,
            refreshTokenManager: $refreshManager,
            refreshTokenExtractor: $refreshExtractor,
        );

        $authenticator->authenticate($request);
    })->throws(InvalidCredentialsException::class, 'Invalid refresh token');

    it('delegates success to custom success handler when configured', function () {
        $request = makeRequest('GET', '/api/profile');
        $token = makeTokenMock('user-1');
        $passport = new Passport('user-1', fn () => new JWTUser('user-1', []));

        $expectedResponse = Mockery::mock(ResponseInterface::class);
        $successHandler = Mockery::mock(AuthenticationSuccessHandlerInterface::class);
        $successHandler->shouldReceive('handle')->once()->with('guard', $request, $token, $passport)->andReturn($expectedResponse);

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
            refreshTokenEnabled: false,
            successHandler: $successHandler,
        );

        expect($authenticator->onAuthenticationSuccess('guard', $request, $token, $passport))->toBe($expectedResponse);
    });

    it('revokes old refresh token and reissues both tokens on refresh success', function () {
        $request = makeRequest('POST', '/api/refresh');
        $token = makeTokenMock('user-2');
        $passport = new Passport('user-2', fn () => new JWTUser('user-2', []));

        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor->shouldReceive('extract')->once()->with($request)->andReturn('old-refresh-token');

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManager->shouldReceive('issue')->once()->with($token)->andReturn(new AccessToken('new-access-token', 600));

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('revoke')->once()->with('old-refresh-token');
        $refreshManager->shouldReceive('issue')->once()->with($token)->andReturn(new RefreshToken('new-refresh-token', 3600));

        $authenticator = new JWTAuthenticator(
            refreshPath: '/api/refresh',
            accessTokenManager: $accessManager,
            accessTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
            refreshTokenEnabled: true,
            refreshTokenManager: $refreshManager,
            refreshTokenExtractor: $refreshExtractor,
        );

        $response = $authenticator->onAuthenticationSuccess('guard', $request, $token, $passport);

        expect($response)->not->toBeNull();

        $payload = json_decode((string) $response->getBody(), true);
        expect($payload)->toBe([
            'access_token' => 'new-access-token',
            'expires_in' => 600,
            'refresh_token' => 'new-refresh-token',
        ]);
    });

    it('returns false for interactive mode', function () {
        $authenticator = new JWTAuthenticator(
            refreshPath: '',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
            refreshTokenEnabled: false,
        );

        expect($authenticator->isInteractive())->toBeFalse();
    });

    it('requires refresh_path when refresh token is enabled', function () {
        new JWTAuthenticator(
            refreshPath: '',
            accessTokenManager: Mockery::mock(AccessTokenManagerInterface::class),
            accessTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
            refreshTokenEnabled: true,
            refreshTokenManager: Mockery::mock(RefreshTokenManagerInterface::class),
            refreshTokenExtractor: Mockery::mock(AccessTokenExtractorInterface::class),
        );
    })->throws(InvalidArgumentException::class, 'The "refresh_path" option is required when refresh_token_enabled is true.');
});
