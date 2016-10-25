<?php namespace MaddHatter\GnuPG\Exceptions;

class PublicKeyNotFound extends \RuntimeException
{

    public function __construct($fingerprint, $server = null)
    {
        $message = "Could not find a public OpenPGP key with fingerprint [{$$fingerprint}]";

        if ($server) {
            $message .= " (searched [{$server}] for key)";
        }

        parent::__construct($message);
    }


}