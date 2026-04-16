<?php

declare(strict_types=1);

use GaaraHyperf\JWT\JWTCustomClaimAwareUserInterface;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use GaaraHyperf\JWT\JWTSuccessHandler;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\User\UserInterface;
use Psr\Http\Message\ResponseInterface as PsrResponseInterface;

it('passes custom jwt claims from the authenticated user to the success handler', function (): void {
    $request = makeRequest('POST', '/login');
    $requestToken = makeTokenMock('user-1');
    $response = Mockery::mock(PsrResponseInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);

    $user = new class implements UserInterface, JWTCustomClaimAwareUserInterface {
        public function getIdentifier(): string
        {
            return 'user-1';
        }

        public function getJWTCustomClaims(): array
        {
            return ['role' => 'admin'];
        }
    };

    $passport = new Passport('user-1', fn (): UserInterface => $user);

    $jwtManager->shouldReceive('issue')->once()->with($requestToken, ['role' => 'admin'])->andReturn($response);

    $handler = new JWTSuccessHandler($jwtManager);

    expect($handler->handle('api', $request, $requestToken, $passport))->toBe($response);
});

it('issues tokens without custom claims for ordinary users', function (): void {
    $request = makeRequest('POST', '/login');
    $requestToken = makeTokenMock('user-1');
    $response = Mockery::mock(PsrResponseInterface::class);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);

    $user = new class implements UserInterface {
        public function getIdentifier(): string
        {
            return 'user-1';
        }
    };

    $passport = new Passport('user-1', fn (): UserInterface => $user);

    $jwtManager->shouldReceive('issue')->once()->with($requestToken, [])->andReturn($response);

    $handler = new JWTSuccessHandler($jwtManager);

    expect($handler->handle('api', $request, $requestToken, $passport))->toBe($response);
});
