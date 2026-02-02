<?php
declare(strict_types=1);

require __DIR__ . '/src/SignerApp.php';

$app = new SignerApp(__DIR__ . '/.env');
$app->handle();
