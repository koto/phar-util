#!/usr/bin/env php
<?php
/**
 * Build a phar archive and sign it using a private key from a given file
 *
 * You need to have some keys generated first - phar-generate-cert
 *
 * This file is part of the PharUtil library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package PharUtil
 */

// Include the Console_CommandLine package.
require_once 'Console/CommandLine.php';

// create the parser
$parser = new Console_CommandLine(array(
    'description' => 'Build a phar archive and sign it using a private key from a given file',
    'version'     => '@package_version@',
    'name'        => 'phar-build',
));

// add an option to make the program verbose
$parser->addOption('src', array(
    'short_name'  => '-s',
    'long_name'   => '--src',
    'action'      => 'StoreString',
    'default'     => './src',
    'description' => "Source files directory\n(./src)"
));

$parser->addOption('private', array(
    'short_name'  => '-p',
    'long_name'   => '--private',
    'action'      => 'StoreString',
    'default'     => './cert/priv.pem',
    'description' => "Private key file (PEM) to generate signature\n(./cert/priv.pem)"
));

$parser->addOption('public', array(
    'short_name'  => '-P',
    'long_name'   => '--public',
    'action'      => 'StoreString',
    'default'     => './cert/pub.pem',
    'description' => "Public key file (PEM) to verify signature\n(./cert/pub.pem)"
));

$parser->addOption('nosign', array(
    'short_name'   => '-n',
    'long_name'   => '--ns',
    'action'      => 'StoreTrue',
    'description' => 'Don\'t sign the Phar archive'
));

$parser->addOption('phar', array(
    'long_name'   => '--phar',
    'action'      => 'StoreString',
    'default'     => './output.phar',
    'description' => "Output Phar archive filename\n(./output.phar)",
));

// run the parser
try {
    $result = $parser->parse();
} catch (Exception $exc) {
    $parser->displayError($exc->getMessage());
}

$options = $result->options;

echo $parser->name . ' ' . $parser->version . PHP_EOL . PHP_EOL;


// validate parameters
if (substr($options['phar'], -5) !== '.phar') {
    $parser->displayError("Output must have .phar extension, {$options['phar']} given.", 2);
}

if (!$options['nosign']) {
    if (!file_exists($options['private']) || !is_readable($options['private'])) {
        $parser->displayError("Private key in '{$options['private']}' does not exist or is not readable.", 3);
    }

    if (!file_exists($options['public']) || !is_readable($options['public'])) {
        $parser->displayError("Public key in '{$options['public']}' does not exist or is not readable.", 4);
    }
}

if (!is_dir($options['src']) || !is_readable($options['src'])) {
    $parser->displayError("Source directory in '{$options['src']}' does not exist or is not readable.\n,", 5);
}

echo "Building Phar archive from {$options['src']}..." . PHP_EOL;

$dest = $options['phar'];

$priv_file = $options['private']; // path to PEM private file
$pub_file = $options['public']; // path to PEM public file

try {
    foreach (glob($options['phar'] . '*') as $file)
      unlink($file);
    $phar = new Phar($options['phar']);

    // get the private key
    $private_key = file_get_contents($priv_file);
    if (!$private_key) {
        throw new Exception("Could not load private key from '$priv_file'!");
    }

    // apply the signature
    $phar->buildFromDirectory($options['src']);
    // unfortunately Phar disables openssl signing for compressed archives
    // $phar->compress(PHAR::GZ);

    if (!$options['nosign']) {
        echo "Signing the archive with '$priv_file'." . PHP_EOL;
        $phar->setSignatureAlgorithm(Phar::OPENSSL, $private_key);

        // attach the public key for verification
        if (!copy($pub_file, $options['phar'] . '.pubkey')) {
            echo "Attaching public key file." . PHP_EOL;
            throw new RuntimeException('Could not copy public key!');
        }
    }

    echo PHP_EOL . "{$options['phar']} created, exiting." . PHP_EOL;

} catch (Exception $e) {
    unlink($dest);
    echo "Error: " . $e->getMessage() . "\n";
}