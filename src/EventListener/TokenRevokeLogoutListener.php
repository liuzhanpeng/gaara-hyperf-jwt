<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT\EventListener;

use GaaraHyperf\AccessTokenExtractor\AccessTokenExtractorInterface;
use GaaraHyperf\Event\LogoutEvent;
use GaaraHyperf\JWT\TokenManager\TokenManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * 撤消Token登出监听器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class TokenRevokeLogoutListener implements EventSubscriberInterface
{
    public function __construct(
        private TokenManagerInterface $tokenManager,
        private AccessTokenExtractorInterface $accessTokenExtractor,
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

        $accessToken = $this->accessTokenExtractor->extract($event->getRequest());
        if (is_null($accessToken)) {
            return;
        }

        $this->tokenManager->revoke($accessToken);
    }
}
