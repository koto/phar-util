<?php
/**
 * Exemplary file - download a signed phar archive from any location, verifying its public key
 *
 * This file is part of the Remote-Phar library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package remote-phar
 */

require_once 'RemotePharDownloader.php';

$d = new RemotePharDownloader('./tmp', './cert/pub.pem');

// here the local URI is used, but it could be any remote, e.g.  http:// location
$path = dirname(__FILE__) . '/build/test.phar';

$local_phar = $d->download($path, true);
require_once $local_phar;

echo test();