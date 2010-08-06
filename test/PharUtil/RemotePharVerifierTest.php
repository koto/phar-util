<?php
require_once 'PharUtil/RemotePharVerifier.php';

class PharUtil_RemotePharVerifierTest extends PHPUnit_Framework_TestCase {

    protected $tmp_dir;
    protected $data_dir;
    protected $fetch_dir;
    protected $verified_dir;
    protected $remote_dir;

    public function setUp() {
        $this->tmp_dir = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'tmp';
        $this->data_dir = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'data';

        if (is_dir($this->tmp_dir)) {
            self::deleteDir($this->tmp_dir);
        }
        mkdir($this->tmp_dir);
        mkdir($this->fetch_dir = $this->tmp_dir . '/tmp');
        mkdir($this->verified_dir = $this->tmp_dir . '/verified');

        $this->remote_dir = $this->data_dir . '/phar/';
    }

    public function tearDown() {
        self::deleteDir($this->tmp_dir);
    }

    public function testNotSignedPharsAreInvalid() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $v->fetch($this->remote_dir . 'nosig.phar');
    }

    public function testPharsSignedByOthersAreInvalid() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $v->fetch($this->remote_dir . 'wrongsig.phar');
    }

    public function testInvalidPublicKeyWillStopVerification() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->data_dir . '/cert/trash.pem');

        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $v->fetch($this->remote_dir . 'wrongsig.phar');
    }

    public function testVerifyDoesntCopyToVerifiedDir() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        $ok = $v->verify($this->remote_dir . 'test.phar');
        $this->assertTrue($ok);
        $this->assertFileNotExists($this->verified_dir . '/test.phar');
    }

    /**
     * @dataProvider invalidFiles
     */
    public function testVerifyCorrectlyVerifies($file) {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        try {
            $v->verify($this->remote_dir . $file);
        } catch(PharUtil_SignatureVerificationException $e) {
            $this->assertFileNotExists($this->verified_dir . '/' . $file);
            return;
        }
        $this->fail("PharUtil_SignatureVerificationException was not thrown");
    }

    /**
     * @dataProvider invalidFiles
     */
    public function testVerifyCleansUpOnFailure($file) {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        try {
            $v->verify($this->remote_dir . $file);
        } catch(PharUtil_SignatureVerificationException $e) {
            $this->assertFileNotExists($this->verified_dir . '/' . $file);
            $files = glob($this->fetch_dir . '/*');
            $this->assertEquals(0, count($files));
            return;
        }
        $this->fail("PharUtil_SignatureVerificationException was not thrown");
    }

    /**
     * @dataProvider invalidFiles
     */
    public function testFetchCleansUpOnFailure($file) {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        try {
            $v->fetch($this->remote_dir . $file);
        } catch(PharUtil_SignatureVerificationException $e) {
            $this->assertFileNotExists($this->verified_dir . '/' . $file);
            $files = glob($this->fetch_dir . '/*');
            $this->assertEquals(0, count($files));
            return;
        }
        $this->fail("PharUtil_SignatureVerificationException was not thrown");
    }

    public function invalidFiles() {
        return array(
            array('wrongsig.phar'),
            array('nosig.phar'),
            array('nosigmodified.phar'),
            array('modified.phar'),
            array('test.phar.gz'),
        );
    }

    public function testModifiedPharsAreInvalid() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $v->fetch($this->remote_dir . 'modified.phar');
    }

    public function testNoPubkeyWillPassNotSignedPhars() {
        // no public key given
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, null);

        $ok = $v->fetch($this->remote_dir . 'nosig.phar');
        $this->assertFileExists($ok);
        $this->assertFileEquals($this->remote_dir . 'nosig.phar', $ok);

        // gzips are ok withot pubkey verification
        $ok = $v->fetch($this->remote_dir . 'test.phar.gz');
        $this->assertFileExists($ok);
        $this->assertFileEquals($this->remote_dir . 'test.phar.gz', $ok);
    }

    /**
     * @dataProvider openSslFiles
     */
    public function testNoPubkeyWillErrorOnAllSignedPhars($file) {
        // no public key given
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, null);

        // this will pass (thankyou Phar :( )
        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $ok = $v->fetch($this->remote_dir . $file);
    }

    public function openSslFiles() {
        return array(
            array('wrongsig.phar'),
            array('modified.phar'),
            array('test.phar'),
        );
    }

    public function testNoPubkeyWillCheckOtherChecksums() {
        // no public key given
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, null);

        // simulate transfer error (SHA-1 checksum, but file is modified)
        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $ok = $v->fetch($this->remote_dir . 'nosigmodified.phar');
    }

    /**
     * @dataProvider invalidFilenames
     */
    public function testFilenameChecking($filename) {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, null);
        $this->setExpectedException('RuntimeException', null, PharUtil_RemotePharVerifier::ERR_INVALID_PHAR_FILENAME);
        $v->fetch($this->remote_dir . $filename);
    }

    public function invalidFilenames() {
        return array(
            array('test.mp3'),
            array('test.phar.gz.gz'),
            array(''),
        );
    }

    public function testMovingToVerifiedDirectory() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        $ok = $v->fetch($this->remote_dir . 'test.phar');
        $this->assertFileExists($ok);
        $this->assertFileEquals($ok, $this->remote_dir . '/test.phar');
        $this->assertEquals($this->verified_dir . '/test.phar', $ok);
    }

    public function testInvalidFileWontReachVerifiedDirectory() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());
        $ok = $v->fetch($this->remote_dir . 'test.phar');
        $this->assertFileExists($ok);
        $this->assertFileEquals($this->remote_dir . '/test.phar', $ok);

        // lets be evil now
        copy($this->data_dir . '/phar/wrongsig.phar', $this->tmp_dir . '/test.phar');
        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $v->fetch($this->tmp_dir . '/test.phar', true);

        // verified file not overwritten
        $this->assertFileEquals($this->remote_dir . '/test.phar', $ok);
    }

    public function testRenamingAFileStillMaintainsValidation() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());

        copy($this->data_dir . '/phar/wrongsig.phar', $this->tmp_dir . '/test.phar');
        $this->setExpectedException('PharUtil_SignatureVerificationException');
        $ok = $v->fetch($this->tmp_dir . '/test.phar');
    }

    public function testIncludingVerifiedFile() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());
        $ok = $v->fetch($this->remote_dir . 'test.phar');

        ob_start();
        include $ok;
        $a = ob_get_contents();
        ob_end_clean();

        // was everything inside phar ok?
        $this->assertEquals(trim($a), 'Hello from mighty phar archive!');
        $this->assertTrue(function_exists('test'));
        $this->assertEquals('this is test', test());
    }

    public function testVerifyingUsuallyKeepsFilenames() {
        $v = new PharUtil_RemotePharVerifier($this->fetch_dir, $this->verified_dir, $this->getPubKey());
        $ok = $v->fetch($this->remote_dir . 'test.phar');

        $this->assertEquals('test.phar', basename($ok));
    }

    protected function getPubKey() {
        return $this->data_dir . '/cert/pub.pem';
    }

    protected static function deleteDir($dir) {
        $iterator = new RecursiveDirectoryIterator($dir);
        foreach (new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST) as $file) {
          if ($file->isDir()) {
             rmdir($file->getPathname());
          } else {
             unlink($file->getPathname());
          }
        }
        rmdir($dir);
    }
}
