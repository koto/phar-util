#!/usr/bin/env php
<?php
/**
 * Extract contents of a phar archive to a given directory
 *
 * This file is part of the PharUtil library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package PharUtil
 */

// Include the Console_CommandLine package.
require_once 'Console/CommandLine.php';

// create the parser
$parser = new Console_CommandLine(array(
    'description' => 'Extract contents of a phar archive to a given directory',
    'version'     => '@package_version@',
    'name'        => 'phar-extract',
));

$parser->addOption('public', array(
    'short_name'  => '-P',
    'long_name'   => '--public',
    'action'      => 'StoreString',
    'description' => "Public key file (PEM) to verify signature.\nIf not given, <pharfilename.phar>.pubkey will be used."
));

$parser->addOption('list', array(
    'short_name'  => '-l',
    'long_name'   => '--list',
    'action'      => 'StoreTrue',
    'description' => "Only list the files, don't extract them."
));


$parser->addArgument('phar', array(
    'action'      => 'StoreString',
    'description' => "Input Phar archive filename e.g. phar.phar",
));

$parser->addArgument('destination', array(
    'action'      => 'StoreString',
    'description' => "Destination directory"
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

if (!file_exists($args['phar']) || !is_readable($args['phar'])) {
    $parser->displayError("Phar in '{$args['phar']}' does not exist or is not readable.", 4);
}

if ($options['public']) {
    if (!file_exists($options['public']) || !is_readable($options['public'])) {
        $parser->displayError("Public key in '{$options['public']}' does not exist or is not readable.", 4);
    }
}

if (!$options['list']) {
    if (!is_dir($args['destination']) || !is_writable($args['destination'])) {
        $parser->displayError("Destination directory in '{$args['destination']}' does not exist or is not writable.\n,", 5);
    }
}

if ($options['public']) {
    $pubkey = $args['phar'] . '.pubkey';
    echo "Copying public key to $pubkey\n";
    if (!@copy($options['public'], $pubkey)) {
        $parser->displayError("Error copying {$options['public']} to $pubkey.\n", 6);
    }
}

$dest = $options['phar'];

try {
    echo "Opening Phar archive: {$args['phar']}..." . PHP_EOL;
    $phar = new Phar($args['phar']);
    $files_count = count($phar);

    if ($options['list']) { //list files
        echo "Listing {$files_count} file(s):" . PHP_EOL;
        foreach (new RecursiveIteratorIterator($phar) as $file) {
            echo preg_replace('#(.*?\.phar)#', '', $file) . PHP_EOL;
        }

    } else { // extract
        if (!Phar::canWrite()) {
            throw new Exception("Phar writing support is disabled in this PHP installation, set phar.readonly=0 in php.ini!");
        }
        echo "Extracting {$files_count} file(s) to: {$args['destination']}..." . PHP_EOL;
        $phar->extractTo($args['destination'], null, true);
    }

    if ($options['public']) {
        unlink($pubkey);
    }

} catch (Exception $e) {
    if ($options['public']) {
        unlink($pubkey);
    }
    $parser->displayError($e->getMessage(), 7);
}


echo PHP_EOL . "All done, exiting." . PHP_EOL;