<?php

declare(strict_types=1);

use GaaraHyperf\JWT\InitListener;
use GaaraHyperf\JWT\ServiceProvider;
use GaaraHyperf\ServiceProvider\ServiceProviderRegisterEvent;
use GaaraHyperf\ServiceProvider\ServiceProviderRegistry;

describe('InitListener', function () {
    it('declares listened event', function () {
        $listener = new InitListener();

        expect($listener->listen())->toBe([
            ServiceProviderRegisterEvent::class,
        ]);
    });

    it('registers jwt service provider', function () {
        $listener = new InitListener();
        $registry = new ServiceProviderRegistry();
        $event = new ServiceProviderRegisterEvent($registry);

        $listener->process($event);

        $providers = $registry->getProviders();
        expect($providers)->toHaveCount(1);
        expect($providers[0])->toBeInstanceOf(ServiceProvider::class);
    });
});
