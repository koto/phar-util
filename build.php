<?php

/**
 * Exemplary file - build a phar archive and sign it using a private key from a given file
 *
 * You need to have some keys generated first - see cert/README
 *
 * This file is part of the Remote-Phar library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package remote-phar
 */
$src = './src'; // source files to be built

$dest = './build/test.phar'; // phar destination file

$priv_file = './cert/priv.pem'; // path to PEM private file
$pub_file = './cert/pub.pem'; // path to PEM public file

try {
    foreach (glob($dest . '*') as $file)
      unlink($file);
    $phar = new Phar($dest);

    // get the private key
    $private_key = file_get_contents($priv_file);
    if (!$private_key) {
        throw new Exception("Could not load private key from '$priv_file'!");
    }

    // apply the signature
    $phar->buildFromDirectory($src);
    // unfortunately Phar disables openssl signing for compressed archives
    // $phar->compress(PHAR::GZ);

    $phar->setSignatureAlgorithm(Phar::OPENSSL, $private_key);

    // attach the public key for verification
    if (!copy($pub_file, $dest . '.pubkey')) {
        throw new RuntimeException('Could not copy public key!');
    }

} catch (Exception $e) {
    unlink($dest);
    echo "Error: " . $e->getMessage() . "\n";
}