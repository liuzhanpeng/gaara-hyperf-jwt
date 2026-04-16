<?php

declare(strict_types=1);

use GaaraHyperf\JWT\ConfigProvider;
use GaaraHyperf\JWT\InitListener;

it('returns the init listener from config provider', function (): void {
    $config = (new ConfigProvider())();

    expect($config)->toHaveKey('listeners')
        ->and($config['listeners'])->toContain(InitListener::class);
});
