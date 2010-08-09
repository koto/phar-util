#!/usr/bin/env php
<?php
/**
 * Generate OpenSSL certificate
 * This is the equivalent of these openssl commands:
 * $ openssl genrsa -out priv.pem 1024
 * $ openssl rsa -in priv.pem -pubout -out pub.pem
 *
 * This file is part of the PharUtil library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package PharUtil
 */

// Include the Console_CommandLine package.
require_once 'Console/CommandLine.php';

// create the parser
$parser = new Console_CommandLine(array(
    'description' => 'Generate OpenSSL certificate',
    'version'     => '@package_version@',
    'name'        => 'phar-generate-cert',
));

$parser->addOption('public', array(
    'short_name'  => '-P',
    'long_name'   => '--public',
    'action'      => 'StoreString',
    'default'     => './pub.pem',
    'description' => "Path to public key file (PEM) to generate\n(./pub.pem by default)"
));

$parser->addOption('private', array(
    'short_name'  => '-p',
    'long_name'   => '--private',
    'action'      => 'StoreString',
    'default'     => './priv.pem',
    'description' => "Path to private key file (PEM) to generate\n(./priv.pem by default)"
));

// run the parser
try {
    $result = $parser->parse();
} catch (Exception $exc) {
    $parser->displayError($exc->getMessage());
}

$options = $result->options;
$args = $result->args;

echo $parser->name . ' ' . $parser->version . PHP_EOL . PHP_EOL;

try {
    // Create the keypair
    $res=openssl_pkey_new();

    // Get private key
    openssl_pkey_export($res, $privkey);

    // Get public key
    $pubkey=openssl_pkey_get_details($res);
    $pubkey=$pubkey["key"];

    if (!@file_put_contents($options['private'], $privkey)) {
        throw new Exception("Error writing private key to {$options['private']}!");
    }
    echo "Private key written to {$options['private']} " . PHP_EOL;

    if (!@file_put_contents($options['public'], $pubkey)) {
        throw new Exception("Error writing public key to {$options['public']}!");
    }

    echo "Public key written to {$options['public']} " . PHP_EOL;

} catch (Exception $e) {
    $parser->displayError($e->getMessage(), 1);
}


echo PHP_EOL . "All done, exiting." . PHP_EOL;

?>