<?php namespace MaddHatter\GnuPG\Exceptions;

class InvalidSecretKeyPassphrase extends \RuntimeException
{

    /**
     * @param string     $fingerprint
     * @param bool       $password
     * @param \Exception $previous
     */
    public function __construct($fingerprint, $password = false, $previous = null)
    {
        parent::__construct("Invalid passphrase for secret key [{$fingerprint}] (used passphrase: " . ($password ? 'YES' : 'NO') . ')', 0, $previous);
    }

}