<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolverInterface;
use GaaraHyperf\JWT\JWTCustomClaimAwareUserInterface;
use GaaraHyperf\JWT\JWTResponseHandler;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\JWT\RefreshToken;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolverInterface;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\User\UserInterface;
use Hyperf\HttpMessage\Server\Response;
use Hyperf\HttpServer\Contract\ResponseInterface as HyperfResponseInterface;

describe('JWTResponseHandler', function () {
    it('returns access token payload only when refresh token is disabled', function () {
        $token = makeTokenMock('user-1');
        $passport = new Passport('user-1', fn () => new JWTUser('user-1', []));

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManager->shouldReceive('issue')->once()->with($token, [])->andReturn(new AccessToken('access-1', 600));

        $accessResolver = Mockery::mock(AccessTokenManagerResolverInterface::class);
        $accessResolver->shouldReceive('resolve')->once()->with('default')->andReturn($accessManager);

        $refreshResolver = Mockery::mock(RefreshTokenManagerResolverInterface::class);
        $refreshResolver->shouldReceive('resolve')->never();

        $payload = null;
        $response = Mockery::mock(HyperfResponseInterface::class);
        $response->shouldReceive('json')->once()->andReturnUsing(function ($data) use (&$payload) {
            $payload = $data;
            return new Response();
        });

        $handler = new JWTResponseHandler(
            accessTokenManagerResolver: $accessResolver,
            refreshTokenManagerResolver: $refreshResolver,
            response: $response,
            refreshTokenEnabled: false,
        );

        $result = $handler->handle('guard', makeRequest('POST', '/login'), $token, $passport);

        expect($result)->toBeInstanceOf(Response::class);
        expect($payload)->toBe([
            'access_token' => 'access-1',
            'expires_in' => 600,
        ]);
    });

    it('returns access and refresh token in body mode', function () {
        $token = makeTokenMock('user-2');
        $passport = new Passport('user-2', fn () => new JWTUser('user-2', []));

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManager->shouldReceive('issue')->once()->with($token, [])->andReturn(new AccessToken('access-2', 600));
        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('issue')->once()->with($token)->andReturn(new RefreshToken('refresh-2', 3600));

        $accessResolver = Mockery::mock(AccessTokenManagerResolverInterface::class);
        $accessResolver->shouldReceive('resolve')->once()->with('default')->andReturn($accessManager);
        $refreshResolver = Mockery::mock(RefreshTokenManagerResolverInterface::class);
        $refreshResolver->shouldReceive('resolve')->once()->with('default')->andReturn($refreshManager);

        $payload = null;
        $response = Mockery::mock(HyperfResponseInterface::class);
        $response->shouldReceive('json')->once()->andReturnUsing(function ($data) use (&$payload) {
            $payload = $data;
            return new Response();
        });

        $handler = new JWTResponseHandler(
            accessTokenManagerResolver: $accessResolver,
            refreshTokenManagerResolver: $refreshResolver,
            response: $response,
            refreshTokenResponseType: 'body',
            refreshTokenEnabled: true,
        );

        $handler->handle('guard', makeRequest('POST', '/login'), $token, $passport);

        expect($payload)->toBe([
            'access_token' => 'access-2',
            'expires_in' => 600,
            'refresh_token' => 'refresh-2',
        ]);
    });

    it('sets refresh token cookie when cookie mode is enabled', function () {
        $token = makeTokenMock('user-3');
        $passport = new Passport('user-3', fn () => new JWTUser('user-3', []));

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManager->shouldReceive('issue')->once()->andReturn(new AccessToken('access-3', 600));
        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('issue')->once()->andReturn(new RefreshToken('refresh-3', 3600));

        $accessResolver = Mockery::mock(AccessTokenManagerResolverInterface::class);
        $accessResolver->shouldReceive('resolve')->once()->andReturn($accessManager);
        $refreshResolver = Mockery::mock(RefreshTokenManagerResolverInterface::class);
        $refreshResolver->shouldReceive('resolve')->once()->andReturn($refreshManager);

        $capturedCookie = null;
        $payload = null;
        $response = Mockery::mock(HyperfResponseInterface::class);
        $response->shouldReceive('withCookie')->once()->andReturnUsing(function ($cookie) use (&$capturedCookie, $response) {
            $capturedCookie = $cookie;
            return $response;
        });
        $response->shouldReceive('json')->once()->andReturnUsing(function ($data) use (&$payload) {
            $payload = $data;
            return new Response();
        });

        $handler = new JWTResponseHandler(
            accessTokenManagerResolver: $accessResolver,
            refreshTokenManagerResolver: $refreshResolver,
            response: $response,
            refreshTokenResponseType: 'cookie',
            refreshTokenCookieName: 'rt',
            refreshTokenCookiePath: '/auth',
            refreshTokenCookieDomain: 'example.com',
            refreshTokenCookieSecure: true,
            refreshTokenCookieHttpOnly: true,
            refreshTokenCookieSameSite: 'strict',
            refreshTokenEnabled: true,
        );

        $handler->handle('guard', makeRequest('POST', '/login'), $token, $passport);

        expect($capturedCookie)->not->toBeNull();
        expect($capturedCookie->getName())->toBe('rt');
        expect($capturedCookie->getValue())->toBe('refresh-3');
        expect($capturedCookie->getPath())->toBe('/auth');
        expect($capturedCookie->getDomain())->toBe('example.com');
        expect($capturedCookie->isSecure())->toBeTrue();
        expect($capturedCookie->isHttpOnly())->toBeTrue();
        expect($capturedCookie->getSameSite())->toBe('strict');
        expect($payload)->toBe([
            'access_token' => 'access-3',
            'expires_in' => 600,
        ]);
    });

    it('passes custom claims from custom-claim-aware user', function () {
        $token = makeTokenMock('user-4');

        $customUser = new class implements UserInterface, JWTCustomClaimAwareUserInterface {
            public function getIdentifier(): string
            {
                return 'user-4';
            }

            public function getJWTCustomClaims(): array
            {
                return ['tenant' => 'acme', 'scope' => ['read']];
            }
        };

        $passport = new Passport('user-4', fn () => $customUser);

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManager->shouldReceive('issue')
            ->once()
            ->with($token, ['tenant' => 'acme', 'scope' => ['read']])
            ->andReturn(new AccessToken('access-4', 600));
        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('issue')->once()->andReturn(new RefreshToken('refresh-4', 3600));

        $accessResolver = Mockery::mock(AccessTokenManagerResolverInterface::class);
        $accessResolver->shouldReceive('resolve')->once()->andReturn($accessManager);
        $refreshResolver = Mockery::mock(RefreshTokenManagerResolverInterface::class);
        $refreshResolver->shouldReceive('resolve')->once()->andReturn($refreshManager);

        $response = Mockery::mock(HyperfResponseInterface::class);
        $response->shouldReceive('json')->once()->andReturn(new Response());

        $handler = new JWTResponseHandler(
            accessTokenManagerResolver: $accessResolver,
            refreshTokenManagerResolver: $refreshResolver,
            response: $response,
            refreshTokenEnabled: true,
        );

        $handler->handle('guard', makeRequest('POST', '/login'), $token, $passport);
    });

    it('throws when response template is invalid json', function () {
        $token = makeTokenMock('user-5');
        $passport = new Passport('user-5', fn () => new JWTUser('user-5', []));

        $accessManager = Mockery::mock(AccessTokenManagerInterface::class);
        $accessManager->shouldReceive('issue')->once()->andReturn(new AccessToken('access-5', 600));

        $accessResolver = Mockery::mock(AccessTokenManagerResolverInterface::class);
        $accessResolver->shouldReceive('resolve')->once()->andReturn($accessManager);

        $refreshResolver = Mockery::mock(RefreshTokenManagerResolverInterface::class);

        $response = Mockery::mock(HyperfResponseInterface::class);
        $response->shouldReceive('json')->never();

        $handler = new JWTResponseHandler(
            accessTokenManagerResolver: $accessResolver,
            refreshTokenManagerResolver: $refreshResolver,
            response: $response,
            responseTemplate: 'invalid-json',
            refreshTokenEnabled: false,
        );

        $handler->handle('guard', makeRequest('POST', '/login'), $token, $passport);
    })->throws(InvalidArgumentException::class, 'Response template must be a valid JSON string');
});
