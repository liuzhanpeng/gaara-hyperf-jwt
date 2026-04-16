<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\EventListener;

use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\JWT\JWTokenManager\JWTokenManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * JWT撤消登出监听器.
 */
class JWTRevokeLogoutListener implements EventSubscriberInterface
{
    public function __construct(
        private JWTokenManagerInterface $jwTokenManager,
    ) {
    }

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

        $this->jwTokenManager->revokeRefreshToken($event->getRequest());
    }
}
