<?php
/**
 * Exemplary file - download a signed phar archive from any location, verifying its public key
 *
 * This file is part of the Remote-Phar library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package PharUtil
 */
 
require_once 'PharUtil/RemotePharVerifier.php';

$d = new PharUtil_RemotePharVerifier('./tmp', './verified', './cert/pub.pem');

// here the local URI is used, but it could be any remote, e.g.  http:// location
$path = dirname(__FILE__) . '/build/test.phar';

$local_phar = $d->fetch($path, true);

echo $path, ' => ', $local_phar, PHP_EOL;

require_once $local_phar;

echo test() . PHP_EOL;