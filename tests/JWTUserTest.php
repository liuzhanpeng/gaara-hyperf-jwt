<?php

declare(strict_types=1);

use GaaraHyperf\JWT\JWTUser;

it('exposes jwt user data', function (): void {
    $user = new JWTUser('user-1', ['role' => 'admin']);

    expect($user->getIdentifier())->toBe('user-1')
        ->and($user->getAttributes())->toBe(['role' => 'admin']);
});
