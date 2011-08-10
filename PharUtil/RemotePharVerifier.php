<?php
if(!class_exists('PharUtil_SignatureVerificationException', false) {
    require_once 'PharUtil/SignatureVerificationException.php';
}

/**
 * Downloads remote signed Phar archives to local directory and assigns
 * them local public key file used to verify code signature.
 *
 * Use this class if you have a remotely distributed code and need to make sure
 * that the donwloaded (and later executed) code is signed by a known entity.
 *
 * Public key is never downloaded and needs to be distributed separately from the code
 * (e.g. stored together with local part of an application).
 *
 * Example:
 * <code>
 * $verifier = new PharUtil_RemotePharVerifier('/tmp', './lib', './cert/public.pem');
 * try {
 *   $verified_file = $verifier->fetch("http://example.com/library.phar");
 *   // $verified_file contains absolute filepath of a downloaded file
 *   // with signature verified from './cert/public.pem'
 *
 *   include_once $verified_file;
 *   // or
 *   include_once 'phar://' . $verified_file . '/some/file/within.php';
 *   // or
 *   echo file_get_contents('phar://' . $verified_file . '/readme.txt');
 *
 * } catch (Exception $e) {
 *   // verification failed
 * }
 * </code>
 * Limitations:
 *  - Compressed Phar archives (Phar::isCompresses()) at this moment
 *    cannot be verified with OpenSSL (Phar limitation).
 *    Use compression while serving the files instead.
 *
 * This file is part of the Remote-Phar library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package PharUtil
 * @version @package_version@
 */
class PharUtil_RemotePharVerifier {

    const PHAR_FILENAME_REGEX = '#\.phar(\.[^.]+$|$)#';

    const UNSAFE_FILENAME_CHARS = '#[^-a-zA-Z0-9._]#';

    const ERR_INVALID_PHAR_FILENAME = 1;

    /**
     * @var string $fetch_dir Temporary directory for downloaded code
     */
    protected $fetch_dir;

    /**
     * @var string|null $verified_dir (optional) Verified Phar archives are moved to this directory
     */
    protected $verified_dir;

    /**
     * @var string|null (Optional) path to a public key file to be assigned to downloaded phar archives
     */
    protected $pub_key_file = null;

    /**
     * Constructor for the class.
     * @param string $fetch_dir temporary directory for the files
     * @param string $verified_dir directory for verified archives
     * @param string $pub_key_file path of a PEM file with public key
     * @throws RuntimeException
     */
    public function __construct($fetch_dir, $verified_dir, $pub_key_file = null) {
        if (!class_exists('Phar')) {
            throw new RuntimeException("Phar is not enabled in this PHP configuration!");
        }

        $this->fetch_dir = $fetch_dir;
        if (!is_dir($this->fetch_dir)) {
            throw new RuntimeException("Temporary directory $fetch_dir does not exist!");
        }

        $this->verified_dir = $verified_dir;
        if (!is_dir($this->verified_dir)) {
            throw new RuntimeException("Verified directory $verified_dir does not exist!");
        }

        $this->pub_key_file = $pub_key_file;

        if (!is_null($this->pub_key_file) && !in_array('OpenSSL', Phar::getSupportedSignatures())) {
            throw new RuntimeException("No support for OpenSSL signatures in this PHP configuration!");
        }
    }

    /**
     * Downloads a Phar archive to a local directory and verifies its signature
     * If it matches, the archive is copied to verified_dir.
     *
     * @param string $phar_path Phar archive URI (e.g. /path/to/local/phar.phar or http://path/to/remote/phar.phar )
     * @param bool $overwrite should we overwrite already present local file?
     * @throws RuntimeException
     * @throws PharUtil_SignatureVerificationException
     */
    public function fetch($phar_path, $overwrite = false) {
        $this->assertValidPharURI($phar_path);
        $local_path = $this->getLocalPath($phar_path);

        $dest_file = $this->verified_dir . DIRECTORY_SEPARATOR . $this->stripRandomness($local_path);
        if (file_exists($dest_file)) {
            if ($overwrite) {
                $this->doDelete($local_path);
            } else {
                return realpath($dest_file);
            }
        }

        // copy phar
        if (!copy($phar_path, $local_path)) {
            throw new RuntimeException("Error fetching file '$phar_path'!");
        }

        $this->assertVerified($local_path);

        // copy the file to verified dir
        $local_path = $this->copyToVerified($local_path);

        return realpath($local_path);
    }

    /**
     * Downloads a Phar archive to a local directory and verifies its signature, without copying the file to verified directory
     * @param string $phar_path Phar archive URI (e.g. /path/to/local/phar.phar or http://path/to/remote/phar.phar )
     * @throws RuntimeException
     * @throws PharUtil_SignatureVerificationException
     * @return true
     */
    public function verify($phar_path) {
        $this->assertValidPharURI($phar_path);
        $local_path = $this->getLocalPath($phar_path);

        // copy phar
        if (!copy($phar_path, $local_path)) {
            throw new RuntimeException("Error fetching file '$phar_path'!");
        }

        $this->assertVerified($local_path);

        return true;
    }

    /**
     * Verifies the local file
     * @param bool $overwrite should we overwrite already present local file?
     * @throws RuntimeException
     * @throws PharUtil_SignatureVerificationException
     * @return true
     */
    protected function assertVerified($local_path) {
        // copy pubkey
        if ($this->pub_key_file) {
            if (!copy($this->pub_key_file, $this->getPubkeyFilename($local_path))) {
                throw new RuntimeException("Error copying public key file!");
            }
        }
        try {
            $this->verifyPharSignature($local_path);
        } catch (Exception $e) {
            $this->doDelete($local_path); // delete offending files
            throw $e;
        }

        return true;
    }

    /**
     * @internal
     * @param $errno
     * @param $errstr
     */
    public function throwException($errno, $errstr) {
        throw new RuntimeException($errstr);
    }

    /**
     * Copies phar archive files to a verified directory.
     * To be called AFTER verification!
     * @param string $local_path
     * @param string path to Phar in verified directory
     */
    protected function copyToVerified($local_path) {
        $local_path = basename($local_path);
        $pubkey_path = $this->getPubkeyFilename($local_path);
        copy($this->fetch_dir . DIRECTORY_SEPARATOR . $local_path, $this->verified_dir . DIRECTORY_SEPARATOR . $this->stripRandomness($local_path));
        if (file_exists($this->fetch_dir . DIRECTORY_SEPARATOR . $pubkey_path)) {
            copy($this->fetch_dir . DIRECTORY_SEPARATOR . $pubkey_path, $this->verified_dir . DIRECTORY_SEPARATOR . $this->stripRandomness($pubkey_path));
        }

        return $this->verified_dir . DIRECTORY_SEPARATOR . $this->stripRandomness($local_path);
    }

    /**
     * @internal
     */
    protected function stripRandomness($filename) {
        return preg_replace('#^\d+-#', '', $filename);
    }

    /**
     * @internal
     */
    protected function addRandomness($filename) {
        return rand(0, 100000) . '-' . $filename;
    }

    /**
     * Verifies that a Phar archive has is OpenSSL-signed and the signature is valid
     * @param string path to Phar archive
     * @throws SignatureVerificationException
     */
    protected function verifyPharSignature($local_path) {
        try {
            // When public key is invalid, openssl throws a
            // 'supplied key param cannot be coerced into a public key' warning
            // and phar ignores sig verification.
            // We need to protect from that by catching the warning
            set_error_handler(array($this, 'throwException'));
            $phar = new Phar($local_path); // here the verification happens
            restore_error_handler();

            $sig = $phar->getSignature();

            unset($phar);
            if ($this->pub_key_file && $sig['hash_type'] !== 'OpenSSL') {
                throw new PharUtil_SignatureVerificationException("This phar is not signed with OpenSSL!");
            }
        } catch (UnexpectedValueException $e) {
            throw new PharUtil_SignatureVerificationException($e->getMessage());
        } catch (RuntimeException $e) {
            throw new PharUtil_SignatureVerificationException($e->getMessage());
        }

        return true;
    }

    /**
     * Performs the deletion
     *
     * @param string $local_path
     */
    protected function doDelete($local_path) {
        unlink($local_path);

        if (file_exists($file = $this->getPubkeyFilename($local_path))) {
            unlink($file);
        }
    }

    /**
     * Return Phar compatible filename for public key for a given Phar archive
     * @param string $path
     * @return string
     */
    protected function getPubkeyFilename($path) {
        return $this->stripCompressionSuffix($path) . '.pubkey';
    }

    /**
     * @internal
     * @param string $remote_path
     * @return string
     */
    protected function getLocalPath($remote_path) {
        $suffix = '';
        $match = array();
        if (preg_match(self::PHAR_FILENAME_REGEX, $remote_path, $match)) {
            $suffix = $match[1];
        }

        // construct safe filename (no extension)
        $remote_file = preg_replace(self::PHAR_FILENAME_REGEX, '', basename($remote_path));
        $filename = preg_replace(self::UNSAFE_FILENAME_CHARS, '-', $remote_file);

        // PHAR or OpenSSL has a bug - if a filename will pass validation for the first time,
        // all subsequent verifies will also pass (even if file contents change)
        // we need to add randomness to file name
        return $this->fetch_dir . '/' . $this->addRandomness($filename  . '.phar' . $suffix);
    }

    /**
     * @internal
     * @param string $path
     * @return string
     */
    protected function stripCompressionSuffix($path) {
        $suffix = '.phar';
        return preg_replace(self::PHAR_FILENAME_REGEX, $suffix, $path);
    }

    /**
     * Asserts that a URI points to a phar archive
     * (Here you may insert additional checks e.g. hostname)
     *
     * @param string $path
     * @throws RuntimeException
     */
    protected function assertValidPharURI($path) {
        if (!preg_match(self::PHAR_FILENAME_REGEX, $path)) {
            throw new RuntimeException("$path does not end with '.phar'!", self::ERR_INVALID_PHAR_FILENAME);
        }
    }

    /**
     * Downloads a file and immediately does a include on it
     * @param string $phar_path
     * @throws RuntimeException
     */
    public function fetchAndInclude($phar_path) {
        $path = $this->fetch($phar_path);
        include $path;
    }

    /**
     * Downloads a file and immediately does a require on it
     * @param string $phar_path
     * @throws RuntimeException
     */
    public function fetchAndRequire($phar_path) {
        $path = $this->fetch($phar_path);
        require $path;
    }

    /**
     * Downloads a file and immediately does a require_once on it
     * @param string $phar_path
     * @throws RuntimeException
     */
    public function fetchAndRequireOnce($phar_path) {
        $path = $this->fetch($phar_path);
        require_once $path;
    }
}
