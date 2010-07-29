<?php
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
 * $downloader = new RemotePharDownloader('/tmp', 'cert/public.pem');
 * try {
 *   $local = $downloader->download("http://example.com/library.phar");
 * } catch (Exception $e) {
 *   // ...
 * }
 *
 * include_once $local; // this will verify the code signature
 *
 * </code>
 *
 * This file is part of the Remote-Phar library.
 * @author Krzysztof Kotowicz <kkotowicz at gmail dot com>
 * @package remote-phar
 */

class RemotePharDownloader {

    /**
     * @var string $tmp_dir Temporary directory for downloaded code
     */
    private $tmp_dir;

    /**
     * @var string|null (Optional) path to a public key file to be assigned to downloaded phar archives
     */
    private $pub_key_file = null;

    /**
     * Constructor for the class.
     * @param string $tmp_dir temporary directory for the files
     * @param string $pub_key_file path of a PEM file with public key
     * @throws RuntimeException
     */
    public function __construct($tmp_dir = './tmp', $pub_key_file = null) {
        $this->tmp_dir = $tmp_dir;
        if (!is_dir($this->tmp_dir)) {
            throw new RuntimeException("Temporary directory $tmp_dir does not exist!");
        }
        $this->pub_key_file = $pub_key_file;
    }

    /**
     * Main method - downloads a Phar archive to a local location and verifies its signature
     *
     * @param string $phar_path Phar archive URI (file path, url, ...)
     * @param bool $overwrite should we overwrite already present local file?
     * @throws RuntimeException
     * @throws UnexpectedValueException
     */
    public function download($phar_path, $overwrite = false) {
        $this->assertValidPharURI($phar_path);
        $local_path = $this->getLocalPath($path);

        if (!file_exists($local_path) || $overwrite) {
            // copy phar
            if (!copy($phar_path, $local_path)) {
                throw new RuntimeException("Error downloading file '$phar_path'!");
            }

            // copy pubkey
            if ($this->pub_key_file) {

                if (!copy($this->pub_key_file, $local_path . '.pubkey')) {
                    throw new RuntimeException("Error copying public key file!");
                }

                $phar = new Phar($local_path); // here the verification happens
                $sig = $phar->getSignature();
                unset($phar);
                if ($sig['hash_type'] !== 'OpenSSL')
                    throw new RuntimeException("Downloaded '$phar_path' is not signed with OpenSSL!");

            }
        }

        return $local_path;
    }

    /**
     * Deletes locally stored version of phar archive
     * @param string $phar_path
     * @throws RuntimeException
     * @return bool
     */
    public function delete($phar_path) {
        $this->assertValidPharURI($phar_path);

        $local_path = $this->getLocalPath($path);

        if (file_exists($local_path . '.pubkey')) {
            unlink($local_path . '.pubkey');
        }

        return unlink($local_path);
    }

    /**
     * @internal
     * @param string $remote_path
     * @return string
     */
    protected function getLocalPath($remote_path) {
        return $this->tmp_dir . '/' . md5($remote_path) . '.phar';
    }

    /**
     * Asserts that a URI points to a phar archive
     * (Here you may insert additional checks e.g. hostname)
     *
     * @param string $path
     * @throws RuntimeException
     */
    protected function assertValidPharURI($path) {
        if (!preg_match('#\.phar$#', $path)) {
            throw new RuntimeException("$path does not end with '.phar'!");
        }
    }

    /**
     * Downloads a file and immediately does a include on it
     * @param string $phar_path
     * @throws RuntimeException
     */
    public function downloadAndInclude($phar_path) {
        $path = $this->download($phar_path);
        include $path;
    }

    /**
     * Downloads a file and immediately does a require on it
     * @param string $phar_path
     * @throws RuntimeException
     */
    public function downloadAndRequire($phar_path) {
        $path = $this->download($phar_path);
        require $path;
    }

    /**
     * Downloads a file and immediately does a require_once on it
     * @param string $phar_path
     * @throws RuntimeException
     */
    public function downloadAndRequireOnce($phar_path) {
        $path = $this->download($phar_path);
        require_once $path;
    }
}
