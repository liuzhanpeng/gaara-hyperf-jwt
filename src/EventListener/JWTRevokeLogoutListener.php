<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\EventListener;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * JWT撤消登出监听器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class JWTRevokeLogoutListener implements EventSubscriberInterface
{
    public function __construct(
        private RefreshTokenManagerInterface $refreshTokenManager,
        private AccessTokenExtractorInterface $refreshTokenExtractor,
    ) {}

    public static function getSubscribedEvents()
    {
        return [
            LogoutEvent::class => 'onLogout',
        ];
    }

    public function onLogout(LogoutEvent $event): void
    {
        if ($event->getRequest()->getMethod() !== 'POST') {
            return;
        }

        $refreshToken = $this->refreshTokenExtractor->extract($event->getRequest());
        if (is_null($refreshToken)) {
            return;
        }

        $this->refreshTokenManager->revoke($refreshToken);
    }
}
