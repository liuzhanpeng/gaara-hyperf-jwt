<?php

declare(strict_types=1);

use GaaraHyperf\JWT\AccessToken;

it('stores access token values', function (): void {
    $token = new AccessToken('access-token', 600);

    expect($token->token())->toBe('access-token')
        ->and($token->expiresIn())->toBe(600);
});
