<?php

use phpseclib\Math\BigInteger;

class ExampleSSH {
    private function getInt32($pk, $offset)
    {
        $data = unpack("N", substr($pk, $offset, 4));
        if (!$data || !isset($data[1]))
            throw new \Exception("Unable to decode pk data int32", 500);
        return $data[1];
    }

    private function getHex($pk, $offset, $length) {
        $data = unpack("H*", substr($pk, $offset, $length));
        if (!$data || !isset($data[1]))
            throw new \Exception("Unable to decode pk data hex", 500);
        return $data[1];
    }

    public function verifyPublicKeyString($pk_b64, $message_to_sign, $signed_value_hex)
    {
        $pk = @base64_decode($pk_b64);
        if ($pk === FALSE)
            throw new \Exception("PK base64 decode error FALSE", 500);

        $pklen = strlen($pk);
        if ($pklen < 20)
            throw new \Exception("PK base64 decode error <20", 500);
        $offset = 0;
        $key_type_len = $this->getInt32($pk, $offset); $offset += 4;
        $key_type = substr($pk, $offset, $key_type_len); $offset += $key_type_len;

        if ($key_type != "ssh-rsa") {
            throw new \Exception("Only ssh-rsa keys are allowed.", 500);
        }

        $public_exponent_length = $this->getInt32($pk, $offset); $offset += 4;
        $public_exponent_hex = $this->getHex($pk, $offset, $public_exponent_length); $offset += $public_exponent_length;

        $modulus_length = $this->getInt32($pk, $offset); $offset += 4;
        $modulus = $this->getHex($pk, $offset, $modulus_length);

        $sint = new BigInteger($signed_value_hex, 16);
        $m_int = new BigInteger($modulus, 16);
        $pe = new BigInteger($public_exponent_hex, 16);
        $verify_hash = $sint->modPow($pe, $m_int)->toHex();
        $hash_signature = substr($verify_hash, -40);
        $hash_message = sha1($message_to_sign);
        if ($hash_message === $hash_signature) {
            return true;
        }
        return false;
    }
}


new ExampleSSH()->verifyPublicKeyString($base64_string_from_authorized_keys, $original_message, $signed_value_came_backfrom_ssh_sign_pl)
