<?php

/*
 * (c) Dmitri Petmanson <dpetmanson@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

abstract class Client
{
    /**
     * @var Math_BigInteger Local public ephemeral value
     */
    protected $clientPublicEphemeralValue;

    /**
     * @var Math_BigInteger A generator modulo N
     */
    protected $g;

    /**
     * @var Math_BigInteger Remote public ephemeral value
     */
    protected $hostPublicEphemeralValue;

    /**
     * @var Math_BigInteger Multiplier parameter (K)
     */
    protected $multiplier;

    /**
     * @var Math_BigInteger A large safe prime
     */
    protected $N;

    /**
     * @var string User's salt
     */
    protected $salt;

    /**
     * @var Math_BigInteger Local secret ephemeral value
     */
    protected $secretEphemeralValue;

    /**
     * @var Math_BigInteger Computed session key
     */
    protected $sessionKey;

    /**
     * @var string Hashed session key
     */
    protected $strongSessionKey;

    /**
     * @var string User's username (I)
     */
    protected $username;

    /**
     * SRP Client constructor.
     *
     * @param string $identity    User's identity (username)
     * @param string|null $salt   User's salt
     * @param array|null $options Various options for SRP Client
     */
    public function __construct(string $identity, string $salt = null, array $options = null)
    {
        $this->g = new Math_BigInteger($options['g'] ?? '07', 16);
        $this->multiplier = new Math_BigInteger('03', 16);
        $this->N = new Math_BigInteger(
            $options['N'] ?? '894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7',
            16
        );
        $this->salt = $salt;
        $this->username = $identity;
    }

    /**
     * Sets user's salt
     *
     * @param string $salt
     */
    public function setSalt(string $salt): void
    {
        $this->salt = $salt;
    }

    /**
     * @return string
     */
    public function getSessionKey(): string
    {
        return $this->sessionKey->toHex();
    }

    /**
     * @return string
     */
    public function getStrongSessionKey(): string
    {
        return $this->strongSessionKey;
    }

    /**
     * @return Math_BigInteger Random scrambling parameter
     */
    public function computeRandomScramblingParameter(): Math_BigInteger
    {
        $hash = sha1($this->clientPublicEphemeralValue->toHex() . $this->hostPublicEphemeralValue->toHex());

        return new Math_BigInteger($hash, 16);
    }

    /**
     * @return string
     */
    public function computeClientSessionKeyProof(): string
    {
        $A = $this->clientPublicEphemeralValue->toHex();
        $B = $this->hostPublicEphemeralValue->toHex();
        $I = sha1($this->username);
        $K = $this->strongSessionKey;
        $Ng = sha1($this->N->toHex()) ^ sha1($this->g->toHex());
        $s = $this->salt;

        return sha1($Ng . $I . $s . $A . $B . $K);
    }

    /**
     * @param string $M User's calculated proof of session
     *
     * @return string
     */
    public function computeHostSessionKeyProof(string $M): string
    {
        return sha1($this->clientPublicEphemeralValue->toHex() . $M . $this->strongSessionKey);
    }

    /**
     * Returns hex of public ephemeral value
     *
     * @return string
     */
    abstract public function getPublicEphemeralValue(): string;

    /**
     * @return Math_BigInteger
     * @throws Exception
     */
    public function generateSecretEphemeralValue(): Math_BigInteger
    {
        return new Math_BigInteger($this->getRandomNumber(16), 16);
    }

    /**
     * @param Math_BigInteger $value Secret ephemeral value
     *
     * @return Math_BigInteger Public ephemeral value
     */
    abstract public function computePublicEphemeralValue(Math_BigInteger $value): Math_BigInteger;

    /**
     * Generates both private and public ephemeral values but returns only public value
     *
     * @return Math_BigInteger
     * @throws Exception
     */
    protected function generateEphemeralValues(): Math_BigInteger
    {
        $public = null;

        while (!$public || bcmod($public, $this->N) === 0) {
            $secret = $this->generateSecretEphemeralValue();
            $public = $this->computePublicEphemeralValue($secret);
        }

        $this->secretEphemeralValue = $secret ?? null;

        return $public;
    }

    /**
     * Generate hex string of defined length of random bytes
     *
     * @param int $length
     *
     * @return string
     * @throws Exception
     */
    protected function getRandomNumber(int $length): string
    {
        return bin2hex(random_bytes($length));
    }
}
