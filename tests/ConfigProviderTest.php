<?php

declare(strict_types=1);

use GaaraHyperf\JWT\ConfigProvider;
use GaaraHyperf\JWT\InitListener;

describe('ConfigProvider', function () {
    it('returns listener configuration', function () {
        $provider = new ConfigProvider();

        expect($provider())->toBe([
            'listeners' => [
                InitListener::class,
            ],
        ]);
    });
});
