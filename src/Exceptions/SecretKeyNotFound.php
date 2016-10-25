<?php namespace MaddHatter\GnuPG\Exceptions;

class SecretKeyNotFound extends \RuntimeException
{

    public function __construct($fingerprint, $previous = null)
    {
        parent::__construct("Could not find secret OpenPGP key with fingerprint [{$fingerprint}]", 0, $previous);
    }


}