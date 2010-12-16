#! /usr/bin/env php
<?php
/**
 * Build a list of checksums, to see if we want to rebuild a phar archive
 *
 * This file is part of the PharUtil library.
 * @author Damian Bushong <stratosphere dot programming at gmail dot com>
 * @package PharUtil
 */

require_once 'Console/CommandLine.php';

// create the parser
$parser = new Console_CommandLine(array(
    'description' => 'Check to see if a PHAR archive rebuild is necessary.',
    'version'     => '@package_version@',
    'name'        => 'phar-file-checksums',
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

$parser->addOption('quiet', array(
    'short_name'   => '-q',
    'long_name'   => '--quiet',
    'action'      => 'StoreTrue',
    'description' => 'Suppress most of the output statements.'
));

$parser->addOption('verbose', array(
    'short_name'   => '-v',
    'long_name'   => '--verbose',
    'action'      => 'StoreTrue',
    'description' => 'Outputs additional information to the console.' // in other words, we spam the console with everything we can :3
));

$parser->addOption('checksum_file', array(
    'short_name'  => '-c',
    'long_name'   => '--checksumfile',
    'action'      => 'StoreString',
    'default'     => './checksum-file.json',
    'description' => "JSON file for storing source file checksums \n(./checksum-file.json)."
));

$parser->addOption('nowrites_checksum', array(
    'long_name'   => '--no-save-checksums',
    'action'      => 'StoreTrue',
    'description' => 'Do not save checksums obtained to the checksum file.'
));

// run the parser
try {
    $result = $parser->parse();
} catch (Exception $exc) {
    $parser->displayError($exc->getMessage());
}

$options = $result->options;

// Use a constant to avoid globals.
define('QUIET_MODE', ((bool) $options['quiet']));
define('VERBOSE_MODE', ((bool) $options['verbose']));

if (!QUIET_MODE) {
    echo $parser->name . ' ' . $parser->version . PHP_EOL . PHP_EOL;
}

// validate parameters
if (!class_exists('Phar')) {
    $parser->displayError("No Phar support found, you need to build and enable Phar extension. Exiting...", 10);
}

if (!is_dir($options['src']) || !is_readable($options['src'])) {
    $parser->displayError("Source directory in '{$options['src']}' does not exist or is not readable.\n,", 5);
}

if (!QUIET_MODE) {
    echo "Obtaining file checksums for source files in {$options['src']}..." . PHP_EOL;
}

try {
    $iterator = new RecursiveDirectoryIterator($options['src']);

    $iterator = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::SELF_FIRST);

    if ($options['exclude_files'] || $options['exclude_dirs']) {
        $iterator = new ExcludeFilesIterator($iterator, $options['exclude_files'], $options['exclude_dirs']);
    }

    // buildFromIterator unfortunately sucks and skips nested directories (?)
    foreach ($iterator as $file) {
        if (!$iterator->isDot()) {
            if ($file->isFile()) {
                $hash = $checksums[(string) $file] = hash_file('sha1', (string) $file); // @note can easily change the first param of hash_file into an option that can be set via a command line parameter.
                if(VERBOSE_MODE) {
                    echo "file hash for '$file': $hash\n";
                }
            }
        }
    }

    try {
        // If the checksum file doesn't exist, we'll just say a rebuild is needed.
        if (!file_exists($options['checksum_file'])) {
            throw new Exception("Rebuild required, checksum file not present", 12);
        }

        $filestates = json_decode(file_get_contents($options['checksum_file']), true);

        foreach ($checksums as $file => $checksum) {
            // On the first different thing, bail out and flag this as needing a rebuild.
            if (!isset($filestates[$file])) {
                throw new Exception ("Rebuild required, new file '$file' detected.", 12);
            }
            if ($filestates[$file] !== $checksum) {
                if(!VERBOSE_MODE) {
                    throw new Exception("Rebuild required, file '$file' has changed.\n", 12);
                } else { 
                    throw new Exception("Rebuild required, file '$file' has changed.\nPrevious checksum: {$filestates[$file]}\nCurrent checksum: $checksum\n", 12);
                }
            }

            unset($filestates[$file], $checksums[$file]);
        }

        // If there were files not present in one filestate or the other, then we obviously need a rebuild.
        if (!empty($checksums) || !empty($filestates)) {
            throw new Exception("Rebuild required, one or more files have been deleted or added.", 12);
        }
    }
    catch(Exception $e) {
        // Dump our file of checksums now, so that we can use it later.
        if (empty($options['nowrite_checksums'])) {
            file_put_contents($options['checksum_file'], json_encode($checksums));
        }
        if (!QUIET_MODE) {
            $parser->displayError($e->getMessage(), $e->getCode());
        } else {
            exit($e->getCode());
        }
    }

    if (!QUIET_MODE) {
        echo "Rebuild not required.\n";
        exit(0);
    }

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    exit(1);
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
                    if(!QUIET_MODE) {
                        echo "skipping $file\n";
                    }
                    return false;
                }
            }
        }

        foreach ($this->exclude_path as $pattern) {
            if (preg_match($pattern, $file->getPathname())) {
                if(!QUIET_MODE) {
                    echo "skipping $file\n";
                }
                return false;
            }
        }

        return true;
    }
}