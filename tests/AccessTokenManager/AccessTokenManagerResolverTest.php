<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerInterface;
use GaaraHyperf\JWT\AccessTokenManager\AccessTokenManagerResolver;

describe('AccessTokenManagerResolver', function () {
    it('resolves manager and reuses cached instance', function () {
        $calls = 0;
        $manager = Mockery::mock(AccessTokenManagerInterface::class);

        $resolver = new AccessTokenManagerResolver([
            'default' => function () use (&$calls, $manager) {
                ++$calls;
                return $manager;
            },
        ]);

        $first = $resolver->resolve('default');
        $second = $resolver->resolve('default');

        expect($first)->toBe($manager);
        expect($second)->toBe($manager);
        expect($calls)->toBe(1);
    });

    it('throws when manager is undefined', function () {
        $resolver = new AccessTokenManagerResolver([]);
        $resolver->resolve('missing');
    })->throws(InvalidArgumentException::class, 'AccessToken Manager "missing" is not defined');
});
