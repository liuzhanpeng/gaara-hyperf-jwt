<?php

declare(strict_types=1);

use GaaraHyperf\JWT\RefreshToken;

it('stores refresh token values', function (): void {
    $token = new RefreshToken('refresh-token', 3600);

    expect($token->token())->toBe('refresh-token')
        ->and($token->expiresIn())->toBe(3600);
});
