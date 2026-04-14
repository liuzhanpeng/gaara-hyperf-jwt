<?php

declare(strict_types=1);

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\JWT\EventListener\JWTRevokeLogoutListener;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;

describe('JWTRevokeLogoutListener', function () {
    it('subscribes to logout event', function () {
        expect(JWTRevokeLogoutListener::getSubscribedEvents())->toBe([
            LogoutEvent::class => 'onLogout',
        ]);
    });

    it('revokes refresh token on post logout request', function () {
        $request = makeRequest('POST', '/logout');
        $event = new LogoutEvent(makeTokenMock(), $request);

        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor->shouldReceive('extract')->once()->with($request)->andReturn('refresh-token');

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('revoke')->once()->with('refresh-token');

        $listener = new JWTRevokeLogoutListener($refreshManager, $refreshExtractor);
        $listener->onLogout($event);
    });

    it('does nothing for non-post request', function () {
        $request = makeRequest('GET', '/logout');
        $event = new LogoutEvent(makeTokenMock(), $request);

        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor->shouldReceive('extract')->never();

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('revoke')->never();

        $listener = new JWTRevokeLogoutListener($refreshManager, $refreshExtractor);
        $listener->onLogout($event);
    });

    it('does nothing when refresh token is missing', function () {
        $request = makeRequest('POST', '/logout');
        $event = new LogoutEvent(makeTokenMock(), $request);

        $refreshExtractor = Mockery::mock(AccessTokenExtractorInterface::class);
        $refreshExtractor->shouldReceive('extract')->once()->with($request)->andReturn(null);

        $refreshManager = Mockery::mock(RefreshTokenManagerInterface::class);
        $refreshManager->shouldReceive('revoke')->never();

        $listener = new JWTRevokeLogoutListener($refreshManager, $refreshExtractor);
        $listener->onLogout($event);
    });
});
