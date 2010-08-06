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

$parser->addOption('src', array(
    'short_name'  => '-s',
    'long_name'   => '--src',
    'action'      => 'StoreString',
    'default'     => './src',
    'description' => "Source files directory\n(./src)"
));

$parser->addOption('exclude_files', array(
    'short_name'  => '-x',
    'long_name'   => '--exclude',
    'action'      => 'StoreString',
    'default'     => '~$',
    'description' => "Space separated regular expressions of filenames that should be excluded\n(\"~$\" by default)"
));

$parser->addOption('exclude_dirs', array(
    'short_name'  => '-X',
    'long_name'   => '--exclude-dir',
    'action'      => 'StoreString',
    'default'     => '/\.svn /\.git',
    'description' => "Space separated regular expressions of directories that should be excluded\n(\"/\.svn /\.git\" by default)"
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
if (!Phar::canWrite()) {
    $parser->displayError("Phar writing support is disabled in this PHP installation, set phar.readonly=0 in php.ini!", 10);
}

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

    $iterator = new RecursiveDirectoryIterator($options['src']);

    $iterator = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::SELF_FIRST);

    if ($options['exclude_files'] || $options['exclude_dirs']) {
        $iterator = new ExcludeFilesIterator($iterator, $options['exclude_files'], $options['exclude_dirs']);
    }

    // buildFromIterator unfortunately sucks and skips nested directories (?)
    foreach ($iterator as $file) {
        echo "adding " . $file . PHP_EOL;
        if ($file->isFile()) {
            $phar->addFile($file, str_replace($options['src'], '', $file));
        }
        if ($file->isDir()) {
            // this also doesn't work :(
            $phar->addEmptyDir(str_replace($options['src'], '', $file));
        }
    }

    //$phar->buildFromIterator($iterator, $options['src']);

    // unfortunately Phar disables openssl signing for compressed archives
    // $phar->compress(PHAR::GZ);

    if (!$options['nosign']) {
        // apply the signature
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
    @unlink($dest);
    echo "Error: " . $e->getMessage() . "\n";
}

class ExcludeFilesIterator extends FilterIterator {
    protected $exclude_file;
    protected $exclude_path;

    public function __construct(Iterator $i, $exclude_file, $exclude_path) {
        parent::__construct($i);
        $exclude_file = array_map(array($this, 'makeRegExp'), preg_split("/ +/", $exclude_file, -1, PREG_SPLIT_NO_EMPTY));
        $exclude_path = array_map(array($this, 'makeRegExp'), preg_split("/ +/", $exclude_path, -1, PREG_SPLIT_NO_EMPTY));
        $this->exclude_file = $exclude_file;
        $this->exclude_path = $exclude_path;
    }

    protected function makeRegExp($pattern) {
        return '!' . $pattern . '!';
    }

    public function accept() {
        $file = $this->current();
        if ($file->isFile()) {
            foreach ($this->exclude_file as $pattern) {
                if (preg_match($pattern, $file->getFilename())) {
                    echo "skipping $file\n";
                    return false;
                }
            }
        }

        foreach ($this->exclude_path as $pattern) {
            if (preg_match($pattern, $file->getPathname())) {
                echo "skipping $file\n";
                return false;
            }
        }

        return true;
    }
}