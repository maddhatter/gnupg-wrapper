<?php namespace MaddHatter\GnuPG\Exceptions;

class ExpiredKey extends \RuntimeException
{

    public function __construct($fingerprint)
    {
        $message = "OpenPGP key with fingerprint [{$fingerprint}] is expired";

        parent::__construct($message);
    }

}