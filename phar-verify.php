#!/usr/bin/env php
<?php
/**
 * Verify Phar archive signature using a public key file
 *
 * This file is part of the PharUtil library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package PharUtil
 */

// Include the Console_CommandLine package.
require_once 'Console/CommandLine.php';
require_once 'PharUtil/RemotePharVerifier.php';

// create the parser
$parser = new Console_CommandLine(array(
    'description' => 'Verify Phar archive signature using a public key file',
    'version'     => '@package_version@',
    'name'        => 'phar-verify',
));

$parser->addOption('public', array(
    'short_name'  => '-P',
    'long_name'   => '--public',
    'action'      => 'StoreString',
    'default'     => './cert/pub.pem',
    'description' => "Public key file (PEM) to verify signature\n(./cert/pub.pem by default)"
));

$parser->addOption('nosign', array(
    'short_name'   => '-n',
    'long_name'   => '--ns',
    'action'      => 'StoreTrue',
    'description' => 'Archive is not signed, don\'t require an OpenSSL signature'
));

$parser->addOption('temp', array(
    'short_name'   => '-t',
    'long_name'   => '--temp',
    'action'      => 'StoreString',
    'description' => 'Temporary directory (' . sys_get_temp_dir() . ' by default)',
));

$parser->addArgument('phar', array(
    'action'      => 'StoreString',
    'description' => "Input Phar archive URI e.g.\n/path/to/local/phar.phar or http://path/to/remote/phar.phar",
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

// validate parameters
if (substr($args['phar'], -5) !== '.phar') {
    $parser->displayError("Input Phar must have .phar extension, {$args['phar']} given.", 2);
}

if ($options['nosign']) {
    $options['public'] = null; // no public key
}

if ($options['public']) {
    if (!file_exists($options['public']) || !is_readable($options['public'])) {
        $parser->displayError("Public key in '{$options['public']}' does not exist or is not readable.", 4);
    }
}

if (!$options['temp']) {
    $options['temp'] = sys_get_temp_dir();
}

try {
    echo "Verifying Phar archive: {$args['phar']}..." . PHP_EOL;

    $v = new PharUtil_RemotePharVerifier($options['temp'], $options['temp'], $options['public']);

    $v->verify($args['phar']);

    echo "Phar archive successfully verified." . PHP_EOL;
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . PHP_EOL;
    exit(1);
}


echo PHP_EOL . "All done, exiting." . PHP_EOL;