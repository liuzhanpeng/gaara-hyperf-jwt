<?php

declare(strict_types=1);

use GaaraHyperf\Exception\InvalidAccessTokenException;
use GaaraHyperf\Exception\InvalidCredentialsException;
use GaaraHyperf\JWT\JWTAuthenticator;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use GaaraHyperf\JWT\JWTUser;
use GaaraHyperf\User\UserInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcher;

it('supports requests that already contain an access token', function (): void {
    $request = makeRequest();
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $eventDispatcher = Mockery::mock(EventDispatcher::class);

    $jwtManager->shouldReceive('isRefreshTokenEnabled')->once()->andReturn(false);
    $jwtManager->shouldReceive('resolveAccessToken')->once()->with($request)->andReturn(new JWTUser('user-1', []));

    $authenticator = new JWTAuthenticator($jwtManager, $userProvider, $eventDispatcher);

    expect($authenticator->supports($request))->toBeTrue()
        ->and($authenticator->isInteractive())->toBeFalse();
});

it('supports refresh-token requests on the configured path', function (): void {
    $request = makeRequest('POST', '/refresh');
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $eventDispatcher = Mockery::mock(EventDispatcher::class);

    $jwtManager->shouldReceive('isRefreshTokenEnabled')->once()->andReturn(true);
    $jwtManager->shouldReceive('refreshTokenPath')->once()->andReturn('/refresh');

    $authenticator = new JWTAuthenticator($jwtManager, $userProvider, $eventDispatcher);

    expect($authenticator->supports($request))->toBeTrue();
});

it('authenticates a valid access token into a passport', function (): void {
    $request = makeRequest();
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $eventDispatcher = Mockery::mock(EventDispatcher::class);
    $jwtUser = new JWTUser('user-1', ['role' => 'admin']);

    $jwtManager->shouldReceive('isRefreshTokenEnabled')->once()->andReturn(false);
    $jwtManager->shouldReceive('resolveAccessToken')->once()->with($request)->andReturn($jwtUser);

    $authenticator = new JWTAuthenticator($jwtManager, $userProvider, $eventDispatcher);
    $passport = $authenticator->authenticate($request);

    expect($passport->getUserIdentifier())->toBe('user-1')
        ->and($passport->getUser())->toBe($jwtUser);
});

it('authenticates a valid refresh token through the user provider', function (): void {
    $request = makeRequest('POST', '/refresh');
    $requestToken = makeTokenMock('user-1');
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $eventDispatcher = Mockery::mock(EventDispatcher::class);

    $user = new class implements UserInterface {
        public function getIdentifier(): string
        {
            return 'user-1';
        }
    };

    $jwtManager->shouldReceive('isRefreshTokenEnabled')->once()->andReturn(true);
    $jwtManager->shouldReceive('refreshTokenPath')->once()->andReturn('/refresh');
    $jwtManager->shouldReceive('resolveRefreshToken')->once()->with($request)->andReturn($requestToken);
    $userProvider->shouldReceive('findByIdentifier')->once()->with('user-1')->andReturn($user);

    $authenticator = new JWTAuthenticator($jwtManager, $userProvider, $eventDispatcher);
    $passport = $authenticator->authenticate($request);

    expect($passport->getUserIdentifier())->toBe('user-1')
        ->and($passport->getUser())->toBe($user);
});

it('rejects invalid refresh tokens during authentication', function (): void {
    $request = makeRequest('POST', '/refresh');
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $eventDispatcher = Mockery::mock(EventDispatcher::class);

    $jwtManager->shouldReceive('isRefreshTokenEnabled')->once()->andReturn(true);
    $jwtManager->shouldReceive('refreshTokenPath')->once()->andReturn('/refresh');
    $jwtManager->shouldReceive('resolveRefreshToken')->once()->with($request)->andReturn(null);

    $authenticator = new JWTAuthenticator($jwtManager, $userProvider, $eventDispatcher);

    expect(fn () => $authenticator->authenticate($request))
        ->toThrow(InvalidCredentialsException::class, 'Invalid refresh token');
});

it('rejects invalid access tokens during authentication', function (): void {
    $request = makeRequest();
    $userProvider = Mockery::mock(UserProviderInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);
    $eventDispatcher = Mockery::mock(EventDispatcher::class);

    $jwtManager->shouldReceive('isRefreshTokenEnabled')->once()->andReturn(false);
    $jwtManager->shouldReceive('resolveAccessToken')->once()->with($request)->andReturn(null);

    $authenticator = new JWTAuthenticator($jwtManager, $userProvider, $eventDispatcher);

    expect(fn () => $authenticator->authenticate($request))
        ->toThrow(InvalidAccessTokenException::class, 'Invalid access token');
});
