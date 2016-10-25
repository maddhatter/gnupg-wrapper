<?php namespace MaddHatter\GnuPG\Exceptions;

class RevokedKey extends \RuntimeException
{

    public function __construct($fingerprint)
    {
        $message = "OpenPGP key with fingerprint [{$fingerprint}] is REVOKED!";

        parent::__construct($message);
    }


}