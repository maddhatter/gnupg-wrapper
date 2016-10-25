<?php namespace MaddHatter\GnuPG;

use MaddHatter\GnuPG\Exceptions\PublicKeyNotFound;

class KeyFinder
{

    /**
     * @param string $fingerprint
     * @param string $server
     * @return string
     * @throws PublicKeyNotFound
     */
    public function get($fingerprint, $server = 'hkps.pool.sks-keyservers.net')
    {
        $key = file_get_contents($this->fetchUrl($fingerprint, $server));

        if ($key === false) {
            throw new PublicKeyNotFound ($fingerprint, $server);
        }

        return $key;

    }

    protected function fetchUrl($fingerprint, $server)
    {
        $server = $server ?: 'hkps.pool.sks-keyservers.net';

        return "https://{$server}/pks/lookup?op=get&search=0x{$fingerprint}";
    }

}