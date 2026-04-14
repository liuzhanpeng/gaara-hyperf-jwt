<?php

declare(strict_types=1);

use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerInterface;
use GaaraHyperf\JWT\RefreshTokenManager\RefreshTokenManagerResolver;

describe('RefreshTokenManagerResolver', function () {
    it('resolves manager and reuses cached instance', function () {
        $calls = 0;
        $manager = Mockery::mock(RefreshTokenManagerInterface::class);

        $resolver = new RefreshTokenManagerResolver([
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
        $resolver = new RefreshTokenManagerResolver([]);
        $resolver->resolve('missing');
    })->throws(InvalidArgumentException::class, 'RefreshToken Manager "missing" is not defined');
});
