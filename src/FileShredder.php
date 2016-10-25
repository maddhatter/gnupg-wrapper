<?php namespace MaddHatter\GnuPG;

class FileShredder
{

    public function shred($file)
    {
        $size   = filesize($file);
        $random = openssl_random_pseudo_bytes($size);

        file_put_contents($file, $random);
        unlink($file);
    }
}