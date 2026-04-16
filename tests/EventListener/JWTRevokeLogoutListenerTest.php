<?php

declare(strict_types=1);

use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\JWT\EventListener\JWTRevokeLogoutListener;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;

it('subscribes to the logout event', function (): void {
    expect(JWTRevokeLogoutListener::getSubscribedEvents())
        ->toBe([LogoutEvent::class => 'onLogout']);
});

it('revokes refresh tokens for post logout requests', function (): void {
    $request = makeRequest('POST', '/logout');
    $event = new LogoutEvent(makeTokenMock(), $request);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);

    $jwtManager->shouldReceive('revokeRefreshToken')->once()->with($request);

    (new JWTRevokeLogoutListener($jwtManager))->onLogout($event);
});

it('ignores non-post logout requests', function (): void {
    $request = makeRequest('GET', '/logout');
    $event = new LogoutEvent(makeTokenMock(), $request);
    $jwtManager = Mockery::mock(JWTokenManagerInterface::class);

    $jwtManager->shouldReceive('revokeRefreshToken')->never();

    (new JWTRevokeLogoutListener($jwtManager))->onLogout($event);
});
