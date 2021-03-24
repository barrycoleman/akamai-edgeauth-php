<?php

namespace barrycoleman\AkamaiEdgeAuth;

class TokenGenerator {
  protected $_config = NULL;

  /**
   * TokenGenerator constructor.
   *
   * Constructs the token generator from the configuration provided.
   * The configuration should be an array. It must contain a 'key' element and should also contain one of
   * 'endTime' or 'windowSeconds'.
   *
   * Configuration elements:
   *   'key' - (required) The encryption key to use. This should be the same value as you enter in the Akamai behavior
   *           Auth Token 2.0 Verification. Must be an even length hexadecimal digit string.
   *   'startTime' - (optional) The unix time the token is valid from. This will default to the current time. Valid
   *           values are any integer greater than zero, and the string 'now'.
   *   'endTime' - (optional) The unix time the token is valid until. This can be any time after the start time. This
   *           must be provided if 'windowSeconds' is not provided.
   *   'windowSeconds' - (optional) The number of seconds the token should be valid for from the start time. This must
   *           be provided if 'endTime' is not provided. 'endTime' has priority over 'windowSeconds' if both are
   *           provided.
   *   'algorithm' - (optional) The algorithm to use to create the token. Must be one of 'sha256', 'sha1', or 'md5'.
   *           Default is 'sha256'.
   *   'escapeEarly' - (optional) Whether to escape strings before generation of the token. Default is false.
   *   'fieldDelimiter' - (optional) The character to place between fields in the token. Default is '~'.
   *           If you intend the token to work in Akamai Auth Token 2.0 Verification behavior you should not change
   *           this.
   *   'aclDelimiter' - (optional) The character to place between entries in an ACL array. Defailt is '!'.
   *           If you intend the token to work in Akamai Auth Token 2.0 Verification behavior you should not change
   *           this.
   *   'verbose' - (optional) Will print out (using echo) the configuration of the component during token generation.
   *           Default is false.
   *   'ip' - (optional) Used for specifying IP address. Uses escapeEarly if set true.
   *   'sessionId' - (optional) Used for specifying a session id. Uses escapeEarly if set true.
   *   'payload' - (optional) Used for specifying a payload. Uses escapeEarly if set true.
   *   'salt' - (optional) Salt added to the token hash. This is deprecated in Akamai and should not be used for
   *           new implementations.
   *   'tokenName' - (optional) This is unused in the current implementation. This would be the name of the cookie,
   *           query parameter or header to use. Default is '__token__'.
   *
   * @param array $config The configuration for the token generator. This should always be passed at least a key.
   * @throws TokenGeneratorException
   */
  public function __construct($config = NULL) {
    if ($config === NULL) {
      $this->_config = [];
    } else {
      $this->_config = $config;
    }

    if (!array_key_exists('tokenName', $this->_config)) {
      $this->_config['tokenName'] = '__token__';
    }

    if (!array_key_exists('key', $this->_config)) {
      throw new TokenGeneratorException('Key must be provided to generate a token');
    }

    if (strlen($this->_config['key']) % 2 !== 0) {
      throw new TokenGeneratorException('Key must be even length');
    }

    if (preg_match("/^[a-f0-9]+$/i", $this->_config['key']) === 0) {
      throw new TokenGeneratorException('Key must be a hex string');
    }

    if (!array_key_exists('algorithm', $this->_config)) {
      $this->_config['algorithm'] = 'sha256';
    }

    if (!array_key_exists('escapeEarly', $this->_config)) {
      $this->_config['escapeEarly'] = false;
    }

    if (!array_key_exists('fieldDelimiter', $this->_config)) {
      $this->_config['fieldDelimiter'] = '~';
    }

    if (!array_key_exists('aclDelimiter', $this->_config)) {
      $this->_config['aclDelimiter'] = '!';
    }

    if (!array_key_exists('verbose', $this->_config)) {
      $this->_config['verbose'] = false;
    }
  }

    /**
     * _escapeEarly()
     *
     * URL encode strings and make sure that all %xx hex encodes are lower case
     *
     * @param string $text
     * @return string
     */
  protected function _escapeEarly($text): string
  {
    if ($this->_config['escapeEarly']) {
      $text = urlencode(utf8_encode($text));
      $text = preg_replace_callback('/%../', static function($match) { return strtolower($match[0]); }, $text);
    }
    return $text;
  }

    /**
     * _array_clone()
     *
     * Creates a deep copy of an array
     *
     * @param array $array
     * @return array
     */
  protected static function _array_clone($array): array
  {
    return array_map(static function($element) {
        if (is_array($element)) {
            return self::_array_clone($element);
        }

        if (is_object($element)) {
            return clone $element;
        }

        return $element;
    }, $array);
  }

    /**
     * _generateToken()
     *
     * This does the actual token generation. The path is used for either the URL or the ACL. It will already
     * have been reduced to a single string by the generateXXXToken() functions as appropriate.  Will generate
     * and URL token if $isURL is true, and an ACL token if $isURL is false.
     *
     * @param string $path
     * @param boolean $isURL
     * @return string
     * @throws TokenGeneratorException
     */
  protected function _generateToken(string $path, bool $isURL): string
  {
    $start_time = $this->_config['startTime'] ?? 'now';
    $end_time = $this->_config['endTime'] ?? NULL;

    if (is_string($start_time) && strtolower($start_time) === 'now') {
      $start_time = time();
    } elseif (is_int($start_time) && $start_time <= 0) {
      throw new TokenGeneratorException('startTime must be a number (>0) or "now"');
    } elseif (!is_int($start_time)) {
      throw new TokenGeneratorException('startTime must be a number (>0) or "now"');
    }

    if (is_int($end_time) && $end_time <= 0) {
      throw new TokenGeneratorException('endTime must be a number (>0)');
    } 

    if (is_int($this->_config['windowSeconds'] ?? NULL) && $this->_config['windowSeconds'] <= 0) {
      throw new TokenGeneratorException('windowSeconds must be a number (>0)');
    }

    if ($end_time === NULL) {
      if (array_key_exists('windowSeconds', $this->_config)) {
        $end_time = $start_time + $this->_config['windowSeconds'];
      } else {
        throw new TokenGeneratorException('You must provide endTime or windowSeconds');
      }
    }

    if ($start_time && $end_time < $start_time) {
      throw new TokenGeneratorException('End time is before start time');
    }

    if (array_key_exists('verbose', $this->_config) && $this->_config['verbose']) {
      echo $this->_to_string($path, $isURL, $start_time, $end_time) . PHP_EOL;
    }

    $newToken = [];

    if (($this->_config['ip'] ?? NULL) !== NULL) {
      $newToken[] = "ip=" . $this->_escapeEarly($this->_config['ip']);
    }

    if (array_key_exists('startTime', $this->_config)) {
      $newToken[] = "st=" . $this->_config['startTime'];
    }

    $newToken[] = "exp=" . $end_time;

    if (!$isURL) {
      $newToken[] = "acl=" . $path;
    }

    if (($this->_config['sessionId'] ?? NULL) !== NULL) {
      $newToken[] = "id=" . $this->_escapeEarly($this->_config['sessionId']);
    }

    if (($this->_config['payload'] ?? NULL) !== NULL) {
      $newToken[] = "data=" . $this->_escapeEarly($this->_config['payload']);
    }

    $hashSource = self::_array_clone($newToken);

    if ($isURL) {
      $hashSource[] = "url=" . $this->_escapeEarly($path);
    }

    if (($this->_config['salt'] ?? NULL) !== NULL) {
      $hashSource[] = "salt=" . $this->_config['salt'];
    }

    $this->_config['algorithm'] = strtolower($this->_config['algorithm']);
    if (!in_array($this->_config['algorithm'], ['sha256', 'sha1', 'md5'])) {
      throw new TokenGeneratorException('Algorithm should be one of sha256, sha1 or md5');
    }

    $hmac = hash_hmac($this->_config['algorithm'], implode($this->_config['fieldDelimiter'], $hashSource), hex2bin($this->_config['key']));
    $newToken[] = "hmac=" . $hmac;

    return implode($this->_config['fieldDelimiter'], $newToken);
  }

    /**
     * generateACLToken()
     *
     * This is the function to create a return an ACL type token.
     * The ACL passed in must be non-null and can be a string or an array of strings.
     *
     * @param string|array $acl  A string or array of strings of the ACL paths
     * @return string            Returns the ACL token
     * @throws TokenGeneratorException
     */
  public function generateACLToken($acl = NULL) {
    if ($acl == NULL) {
      throw new TokenGeneratorException('You must provide an ACL');
    }
    if (is_array($acl)) {
      $acl = implode($this->_config['aclDelimiter'], $acl);
    } elseif (is_string($acl)) {
      $acl = trim($acl);
    } else {
      throw new TokenGeneratorException('ACL must be a string or array');
    }
    return $this->_generateToken($acl, false);
  }

    /**
     * generateURLToken()
     *
     * This is the function to create a return a URL type token.
     * The URL passed in must be non-null and must be a string.
     *
     * @param string $url  A string for the URL path
     * @return string      The URL token
     * @throws TokenGeneratorException
     */
  public function generateURLToken($url = NULL): string
  {
    if ($url === NULL) {
      throw new TokenGeneratorException('You must provide a URL');
    }
    if (!is_string($url)) {
      throw new TokenGeneratorException('URL must be a string');
    }
    return $this->_generateToken($url, true);
  }

    /**
     * _to_string()
     *
     * Produce a string representation of the object. Values passed in from the object during generation
     * support verbose mode in _generateToken(). __toString() produces just configuration with no runtime values.
     *
     * @param null $path
     * @param null $isURL
     * @param null $start_time
     * @param null $end_time
     * @return string
     */
  protected function _to_string($path = NULL, $isURL = NULL, $start_time = NULL, $end_time = NULL): string
  {
    $output = "Akamai Token Generation Parameters" . PHP_EOL;
    if ($isURL === TRUE ) {
      $output .= "   URL            : " . $path . PHP_EOL;
    } elseif ($isURL === FALSE) {
      $output .= "   ACL            : " . $path . PHP_EOL;
    }
    $output .= "   Token Type     : " . ($this->_config['tokenType'] ?? "undefined") . PHP_EOL;
    $output .= "   Token Name     : " . ($this->_config['tokenName'] ?? "undefined") . PHP_EOL;
    $output .= "   Key / Secret   : " . ($this->_config['key'] ?? "undefined") . PHP_EOL;
    $output .= "   Algorithm      : " . ($this->_config['algorithm'] ?? "undefined") . PHP_EOL;
    $output .= "   Salt           : " . ($this->_config['salt'] ?? "undefined") . PHP_EOL;
    $output .= "   IP             : " . ($this->_config['ip'] ?? "undefined") . PHP_EOL;
    $output .= "   Payload        : " . ($this->_config['payload'] ?? "undefined") . PHP_EOL;
    $output .= "   Session ID     : " . ($this->_config['sessionId'] ?? "undefined") . PHP_EOL;
    if ($start_time) { 
      $output .= "   Start Time     : " . $start_time . PHP_EOL;
    }
    $output .= "   Window(Seconds): " . ($this->_config['windowSeconds'] ?? "undefined") . PHP_EOL;
    if ($end_time) {
      $output .= "   End Time       : " . $end_time . PHP_EOL;
    }
    $output .= "   Field Delimiter: " . ($this->_config['fieldDelimiter'] ?? "undefined") . PHP_EOL;
    $output .= "   ACL Delimiter  : " . ($this->_config['aclDelimiter'] ?? "undefined") . PHP_EOL;
    $output .= "   Escape Early   : " . ($this->_config['escapeEarly'] ? "true" : "false") . PHP_EOL;

    return $output;
  }

    /**
     * __toString()
     *
     * Produces a printable representation of the object
     *
     * @return string
     */
  public function __toString(): string
  {
    return $this->_to_string(NULL, NULL, NULL, NULL);
  }
}

class TokenGeneratorException extends \Exception {
  public function __construct($message, $code = 0, \Throwable $previous = NULL) {
    parent::__construct($message, $code, $previous);
  }
 
  public function __toString() {
    return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
  }
}
