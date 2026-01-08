<?php

declare(strict_types=1);

namespace GaaraHyperf\JWT;

use GaaraHyperf\ServiceProvider\ServiceProviderRegisterEvent;
use Hyperf\Event\Contract\ListenerInterface;

/**
 * 初始化监听器
 * 
 * - 注册服务提供者
 * 
 * @author lzpeng <liuzhanpeng@gmail.com>
 */
class InitListener implements ListenerInterface
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
