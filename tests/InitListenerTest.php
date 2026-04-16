<?php

declare(strict_types=1);

use GaaraHyperf\JWT\InitListener;
use GaaraHyperf\JWT\ServiceProvider;
use GaaraHyperf\ServiceProvider\ServiceProviderRegisterEvent;
use GaaraHyperf\ServiceProvider\ServiceProviderRegistry;

it('registers the service provider during initialization', function (): void {
    $listener = new InitListener();
    $registry = new ServiceProviderRegistry();
    $event = new ServiceProviderRegisterEvent($registry);

    $listener->process($event);

    expect($registry->getProviders())->toHaveCount(1)
        ->and($registry->getProviders()[0])->toBeInstanceOf(ServiceProvider::class);
});
