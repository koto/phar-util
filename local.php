<?php
/**
 * Exemplary file - load a signed phar archive, verifying its public key
 *
 * This file is part of the Remote-Phar library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package remote-phar
 */

require_once './build/test.phar';

echo test() . PHP_EOL;