<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\ServiceProvider\ServiceProviderRegisterEvent;
use Hyperf\Event\Contract\ListenerInterface;

/**
 * 注册服务提供器的监听器
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class RegisterListener implements ListenerInterface
{
    public function listen(): array
    {
        return [
            ServiceProviderRegisterEvent::class
        ];
    }

    /**
     * @param ServiceProviderRegisterEvent $event
     * @return void
     */
    public function process(object $event): void
    {
        $registry = $event->serviceProviderRegistry();
        $registry->register(new ServiceProvider());
    }
}
