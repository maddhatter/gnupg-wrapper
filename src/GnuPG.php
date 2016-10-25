<?php namespace MaddHatter\GnuPG;

use gnupg as gpg;
use MaddHatter\GnuPG\Exceptions\ExpiredKey;
use MaddHatter\GnuPG\Exceptions\InvalidSecretKeyPassphrase;
use MaddHatter\GnuPG\Exceptions\PublicKeyNotFound;
use MaddHatter\GnuPG\Exceptions\RevokedKey;
use MaddHatter\GnuPG\Exceptions\SecretKeyNotFound;

class GnuPG
{

    /**
     * @var gpg
     */
    protected $gpg;

    /**
     * @var KeyFinder
     */
    protected $keyFinder;

    /**
     * @var FileShredder
     */
    protected $fileShredder;

    /**
     * @var int
     */
    private $signMode = gpg::SIG_MODE_CLEAR;

    /**
     * @param gpg          $gpg
     * @param KeyFinder    $keyFinder
     * @param FileShredder $fileShredder
     */
    public function __construct(gpg $gpg, KeyFinder $keyFinder, FileShredder $fileShredder)
    {
        $this->gpg          = $gpg;
        $this->keyFinder    = $keyFinder;
        $this->fileShredder = $fileShredder;

        $this->gpg->seterrormode(GNUPG_ERROR_EXCEPTION);
    }

    /**
     * Output binary data
     *
     * @return $this
     */
    public function binary()
    {
        $this->gpg->setarmor(0);

        return $this;
    }

    /**
     * Output ASCII-armored data
     *
     * @return $this
     */
    public function ascii()
    {
        $this->gpg->setarmor(1);
    }

    /**
     * Set signing mode to clear
     *
     * @return GnuPG
     */
    public function clearSign()
    {
        return $this->setSignMode(gpg::SIG_MODE_CLEAR);
    }

    /**
     * Set signing mode to normal
     *
     * @return GnuPG
     */
    public function normalSign()
    {
        return $this->setSignMode(gpg::SIG_MODE_NORMAL);
    }

    /**
     * Set signing mode to detach
     *
     * @return GnuPG
     */
    public function detachSign()
    {
        return $this->setSignMode(gpg::SIG_MODE_DETACH);
    }

    /**
     * Set the signing mode
     *
     * @param $mode
     * @return $this
     */
    public function setSignMode($mode)
    {
        $validModes = [gpg::SIG_MODE_NORMAL, gpg::SIG_MODE_DETACH, gpg::SIG_MODE_CLEAR];

        if ( ! in_array($mode, $validModes)) {
            throw new \InvalidArgumentException("Invalid signing mode: [{$mode}]");
        }

        $this->signMode = $mode;
        $this->gpg->setsignmode($mode);

        return $this;
    }

    /**
     * Add keys for encryption
     *
     * @param array|string $fingerprints
     * @param bool         $search
     * @return $this
     * @throws PublicKeyNotFound|ExpiredKey|RevokedKey
     */
    public function addEncryptKeys($fingerprints, $search = true)
    {
        foreach ((array)$fingerprints as $fingerprint) {
            $this->validateKey($fingerprint, $search);
            $this->gpg->addencryptkey($fingerprint);
        }

        return $this;
    }

    /**
     * Remove all encryption keys
     *
     * @return $this
     */
    public function clearEncryptKeys()
    {
        $this->gpg->clearencryptkeys();

        return $this;
    }

    /**
     * Add keys for decryption
     *
     * @param array|string $fingerprints
     * @param array        $passwords
     * @return $this
     * @internal param array|string $password
     */
    public function addDecryptKeys($fingerprints, $passwords = [])
    {
        $passwords = $this->normalizeKeyPasswords($fingerprints, $passwords);

        foreach ((array)$fingerprints as $i => $fingerprint) {
            if ( ! $this->hasSecretKey($fingerprint)) {
                throw new SecretKeyNotFound($fingerprint);
            }

            $this->gpg->adddecryptkey($fingerprint, $passwords[$i]);
        }

        return $this;
    }

    /**
     * Remove all decryption keys
     *
     * @return $this
     */
    public function clearDecryptKeys()
    {
        $this->gpg->cleardecryptkeys();

        return $this;
    }

    /**
     * Add keys to sign with
     *
     * @param array|string $fingerprints
     * @param array|string $passwords
     * @return $this
     */
    public function addSignKeys($fingerprints, $passwords = [])
    {
        $passwords = $this->normalizeKeyPasswords($fingerprints, $passwords);

        foreach ((array)$fingerprints as $i => $fingerprint) {
            $this->addSecretKey($fingerprint, $passwords[$i]);
        }

        return $this;
    }

    /**
     * Remove all signing keys
     *
     * @return $this
     */
    public function clearSignKeys()
    {
        $this->gpg->clearsignkeys();

        return $this;
    }

    /**
     * Clear all keys
     *
     * @return $this
     */
    public function clearKeys()
    {
        $this->clearEncryptKeys();
        $this->clearDecryptKeys();
        $this->clearSignKeys();

        return $this;
    }

    /**
     * Encrypt data
     *
     * @param string $data
     * @return string
     */
    public function encryptData($data)
    {
        return $this->handleGpg($data, true, false);
    }

    /**
     * Sign data
     *
     * @param $data
     * @return string
     */
    public function signData($data)
    {
        return $this->handleGpg($data, false, true);
    }

    /**
     * Encrypt and sign data
     *
     * @param $data
     * @return string
     */
    public function encryptSignData($data)
    {
        return $this->handleGpg($data, true, true);
    }

    /**
     * Encrypt files
     *
     * @param string|array $files
     * @param bool         $destroy
     * @param string|array $names
     * @return array
     */
    public function encryptFiles($files, $destroy = false, $names = [])
    {
        return $this->handleFiles($files, $destroy, $names, true, false);
    }

    /**
     * Sign files
     *
     * @param string|array $files
     * @param bool         $destroy
     * @param string|array $names
     * @return array
     */
    public function signFiles($files, $destroy = false, $names = [])
    {
        return $this->handleFiles($files, $destroy, $names, false, true);
    }

    /**
     * Encrypt and sign files
     *
     * @param string|array $files
     * @param bool         $destroy
     * @param string|array $names
     * @return array
     */
    public function encryptSignFiles($files, $destroy = false, $names = [])
    {
        return $this->handleFiles($files, $destroy, $names, true, true);
    }

    /**
     * @param string|array $files
     * @param bool         $destroy
     * @param string|array $names
     * @param bool         $encrypt
     * @param bool         $sign
     * @return array
     */
    protected function handleFiles($files, $destroy, $names, $encrypt, $sign)
    {
        if ($names && count((array)$files) !== count((array)$names)) {
            throw new \InvalidArgumentException('Number of files and filenames must match: [' . count((array)$files) . '] files, [' . count((array)$names) . '] names');
        }

        $processedFiles = [];

        foreach ((array)$files as $i => $file) {
            $data      = $this->readFile($file);
            $encrypted = $this->handleGpg($data, $encrypt, $sign);

            if ($destroy) {
                $this->fileShredder->shred($file);
            }

            $name = $this->appendExt($names ? $names[$i] : $file, $encrypt, $sign);

            $processedFiles[$name] = $encrypted;
        }

        return $processedFiles;
    }

    /**
     * Decrypt data
     *
     * @param $data
     */
    public function decryptData($data)
    {
        //TODO
    }

    /**
     * Decrypt a file
     *
     * @param \SplFileInfo|string $file
     */
    public function decryptFile($file)
    {
        //TODO
    }

    /**
     * Import public keys from keyserver
     *
     * @param $fingerprints
     * @param $server
     * @throws PublicKeyNotFound
     */
    public function importKeysFromServer($fingerprints, $server = null)
    {
        foreach ((array)$fingerprints as $fingerprint) {
            $key = $this->keyFinder->get($fingerprint, $server);
            $this->gpg->import($key);
        }
    }

    /**
     * Import an ASCII armored key into GnuPG's keyring
     *
     * @param string $keydata
     */
    public function importKey($keydata)
    {
        return $this->gpg->import($keydata);
    }

    /**
     * Check if a key is revoked
     *
     * @param string $fingerprint
     * @param bool   $search
     * @return bool
     */
    public function isKeyRevoked($fingerprint, $search = true)
    {
        $info = $this->getKeyInfo($fingerprint, $search);

        return $info['revoked'];
    }

    /**
     * Check if a key is expired
     *
     * @param string $fingerprint
     * @param bool   $search
     * @return bool
     */
    public function isKeyExpired($fingerprint, $search = true)
    {
        $info = $this->getKeyInfo($fingerprint, $search);

        return $info['expired'];
    }

    /**
     * Check if a key is expired or revoked
     *
     * @param string $fingerprint
     * @param bool   $search
     * @throws RevokedKey|ExpiredKey
     */
    public function validateKey($fingerprint, $search = true)
    {
        if ($this->isKeyRevoked($fingerprint, $search)) {
            throw new RevokedKey($fingerprint);
        }

        //don't search the key server again, since we (possibly) just did
        if ($this->isKeyExpired($fingerprint, false)) {
            throw new ExpiredKey($fingerprint);
        }

    }

    /**
     * Check if a public key is present
     *
     * @param $fingerprint
     * @return bool
     */
    public function hasPublicKey($fingerprint)
    {
        $info = $this->gpg->keyinfo($fingerprint);

        return count($info) > 0;
    }

    /**
     * Get info about a key
     *
     * @param string $fingerprint
     * @param bool   $search
     * @return array|null
     */
    public function getKeyInfo($fingerprint, $search = true)
    {
        $this->loadKeyOrFail($fingerprint, $search);

        $info = $this->gpg->keyinfo($fingerprint);

        return $info ? $info[0] : null;
    }

    /**
     * @param string $plaintext
     * @param bool   $encrypt
     * @param bool   $sign
     * @return string
     */
    protected function handleGpg($plaintext, $encrypt, $sign)
    {
        if ($encrypt && $sign) {
            return $this->gpg->encryptsign($plaintext);
        }

        if ($encrypt) {
            return $this->gpg->encrypt($plaintext);
        }

        if ($sign) {
            return $this->gpg->sign($plaintext);
        }
    }

    /**
     * Make sure a public key is available (optionally searching a key server)
     *
     * @param string $fingerprint
     * @param bool   $search
     * @throws PublicKeyNotFound
     */
    protected function loadKeyOrFail($fingerprint, $search = true)
    {
        if ( ! $this->hasPublicKey($fingerprint)) {
            if ( ! $search) {
                throw new PublicKeyNotFound($fingerprint);
            }

            $this->importKeys($fingerprint);
        }
    }

    /**
     * Default passwords to empty strings for secret keys
     *
     * @param string|array      $fingerprints
     * @param string|array|null $passwords
     * @return array
     * @throws InvalidArgumentException
     */
    protected function normalizeKeyPasswords($fingerprints, $passwords)
    {
        $fingerprints = (array)$fingerprints;
        $passwords    = (array)$passwords;

        if (count($passwords) && count($passwords) !== count($fingerprints)) {
            throw new \InvalidArgumentException('You provided [' . count($fingerprints) . '] key(s) and [' . count($passwords) .
                '] password(s). If you provide key passwords, the number of passwords and keys must match'
            );
        }

        for ($i = 0; $i < count($fingerprints); $i++) {
            $passwords[] = null;
        }

        return $passwords;
    }

    /**
     * Read a file's content
     *
     * @param $file
     * @return string
     */
    protected function readFile($file)
    {
        if ( ! is_file($file)) {
            throw new \InvalidArgumentException("Could not find file [{$file}].");
        }

        return file_get_contents($file);
    }

    /**
     * Add appropriate suffix to file's name
     *
     * @param string $file
     * @param bool   $encrypt
     * @param bool   $sign
     * @return string
     */
    protected function appendExt($file, $encrypt, $sign)
    {
        if ( ! $encrypt && ! $sign) {
            throw new \InvalidArgumentException("You must either sign or encrypt: encrypting={$encrypt} | signing={$sign}");
        }

        $basename = basename($file);

        if ($encrypt || $this->signMode == gpg::SIG_MODE_NORMAL) {
            return $basename . '.gpg';
        }

        if ($this->signMode == gpg::SIG_MODE_DETACH) {
            return $basename . '.sig';
        }

        if ($this->signMode == gpg::SIG_MODE_CLEAR) {
            return $basename . '.asc';
        }
    }

    protected function addSecretKey($fingerprint, $password)
    {
        try {
            $this->gpg->addsignkey($fingerprint, $password);
        } catch (\Exception $e) {
            throw new SecretKeyNotFound($fingerprint, $e);
        }

        //the key will add OK even if the passphrase is wrong
        //so this tests the ability to sign
        try {
            $this->gpg->sign('test');
        } catch (\Exception $e) {
            throw new InvalidSecretKeyPassphrase($fingerprint, (bool)$password, $e);
        }

    }


}