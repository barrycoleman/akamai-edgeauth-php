<?php

namespace barrycoleman\AkamaiEdgeAuth;

class TokenGenerator {
  protected $_config = NULL;

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

    if (preg_match("/^[a-f0-9]{1,}$/is", $this->_config['key']) === 0) {
      throw new TokenGeneratorException('Key must be a hex string');
    }

    if (!array_key_exists('algorithm', $this->_config)) {
      $this->_config['algorithm'] = 'sha256';
    }

    if (!array_key_exists('escapeEarly', $this->_config)) {
      $this->_config['escapeEarly'] = FALSE;
    }

    if (!array_key_exists('fieldDelimiter', $this->_config)) {
      $this->_config['fieldDelimiter'] = '~';
    }

    if (!array_key_exists('aclDelimiter', $this->_config)) {
      $this->_config['aclDelimiter'] = '!';
    }

    if (!array_key_exists('verbose', $this->_config)) {
      $this->_config['verbose'] = FALSE;
    }
  }

  protected function _escapeEarly($text) {
    if ($this->_config['escapeEarly']) {
      $text = urlencode(utf8_encode($text));
      $text = preg_replace_callback('/%../', function($match) { return strtolower($match[0]); }, $text);
    }
    return $text;
  }

  protected static function _array_clone($array) {
    return array_map(function($element) {
        return ((is_array($element))
            ? self::_array_clone($element)
            : ((is_object($element))
                ? clone $element
                : $element
            )
        );
    }, $array);
  }

  protected function _generateToken($path, $isURL) {
    $start_time = $this->_config['startTime'] ?? 'now';
    $end_time = $this->_config['endTime'] ?? NULL;

    if (gettype($start_time) === 'string' && strtolower($start_time) === 'now') {
      $start_time = time();
    } elseif (gettype($start_time) === 'integer' && $start_time <= 0) {
      throw new TokenGeneratorException('startTime must be a number (>0) or "now"');
    } elseif (gettype($start_time) !== 'integer') {
      throw new TokenGeneratorException('startTime must be a number (>0) or "now"');
    }

    if (gettype($end_time) === 'integer' && $end_time <= 0) {
      throw new TokenGeneratorException('endTime must be a number (>0)');
    } 

    if (gettype($this->_config['windowSeconds'] ?? NULL) === 'integer' && $this->_config['windowSeconds'] <= 0) {
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
      $this->_toString($path, $isURL, $start_time, $end_time);
    }

    $hashSource = [];
    $newToken = [];

    if (($this->_config['ip'] ?? NULL) !== NULL) {
      array_push($newToken, "ip=" . $this->_escapeEarly($this->_config['ip']));
    }

    if (array_key_exists('startTime', $this->_config)) {
      array_push($newToken, "st=" . $this->_config['startTime']);
    }

    array_push($newToken, "exp=" . $end_time);

    if (!$isURL) {
      array_push($newToken, "acl=" . $path);
    }

    if (($this->_config['sessionId'] ?? NULL) !== NULL) {
      array_push($newToken, "id=" . $this->_escapeEarly($this->_config['sessionId']));
    }

    if (($this->_config['payload'] ?? NULL) !== NULL) {
      array_push($newToken, "data=" . $this->_escapeEarly($this->_config['payload']));
    }

    $hashSource = self::_array_clone($newToken);

    if ($isURL) {
      array_push($hashSource, "url=" . $path);
    }

    if (($this->_config['salt'] ?? NULL) !== NULL) {
      array_push($hashSource, "salt=" . $this->_config['salt']);
    }

    $this->_config['algorithm'] = strtolower($this->_config['algorithm']);
    if (!in_array($this->_config['algorithm'], ['sha256', 'sha1', 'md5'])) {
      throw new TokenGeneratorException('Algorithm should be one of sha256, sha1 or md5');
    }

    $hmac = hash_hmac($this->_config['algorithm'], implode($this->_config['fieldDelimiter'], $hashSource), hex2bin($this->_config['key']));
    array_push($newToken, "hmac=" . $hmac);

    return implode($this->_config['fieldDelimiter'], $newToken);
  }

  public function generateACLToken($acl = NULL) {
    if ($acl == NULL) {
      throw new TokenGeneratorException('You must provide an ACL');
    }
    if (gettype($acl) === 'array') {
      $acl = implode($this->_config['aclDelimiter'], $acl);
    } elseif (gettype($acl) === 'string') {
      // do nothing
    } else {
      throw new TokenGeneratorException('ACL must be a string or array');
    }
    return $this->_generateToken($acl, false);
  }

  public function generateURLToken($url = NULL) {
    if ($url == NULL) {
      throw new TokenGeneratorException('You must provide a URL');
    }
    if (gettype($url) !== 'string') {
      throw new TokenGeneratorException('URL must be a string');
    }
    return $this->_generateToken($url, true);
  }

  protected function _toString($path = NULL, $isURL = NULL, $start_time = NULL, $end_time = NULL) {
    echo "Akamai Token Generation Parameters" . PHP_EOL;
    if ($isURL === TRUE ) {
      echo "   URL            : " . $path . PHP_EOL;
    } elseif ($isURL === FALSE) {
      echo "   ACL            : " . $path . PHP_EOL;
    }
    echo "   Token Type     : " . ($this->_config['tokenType'] ?? "undefined") . PHP_EOL;
    echo "   Token Name     : " . ($this->_config['tokenName'] ?? "undefined") . PHP_EOL;
    echo "   Key / Secret   : " . ($this->_config['key'] ?? "undefined") . PHP_EOL;
    echo "   Algorithm      : " . ($this->_config['algorithm'] ?? "undefined") . PHP_EOL;
    echo "   Salt           : " . ($this->_config['salt'] ?? "undefined") . PHP_EOL;
    echo "   IP             : " . ($this->_config['ip'] ?? "undefined") . PHP_EOL;
    echo "   Payload        : " . ($this->_config['payload'] ?? "undefined") . PHP_EOL;
    echo "   Session ID     : " . ($this->_config['sessionId'] ?? "undefined") . PHP_EOL;
    if ($start_time) { 
      echo "   Start Time     : " . $start_time . PHP_EOL;
    }
    echo "   Window(Seconds): " . ($this->_config['windowSeconds'] ?? "undefined") . PHP_EOL;
    if ($end_time) {
      echo "   End Time       : " . $end_time . PHP_EOL;
    }
    echo "   Field Delimiter: " . ($this->_config['fieldDelimiter'] ?? "undefined") . PHP_EOL;
    echo "   ACL Delimiter  : " . ($this->_config['aclDelimiter'] ?? "undefined") . PHP_EOL;
    echo "   Escape Early   : " . ($this->_config['escapeEarly'] ? "true" : "false") . PHP_EOL;
  }

  public function __toString() {
    $this->_toString(NULL, NULL, NULL, NULL);
  }
}

class TokenGeneratorException extends \Exception {
  public function __construct($message, $code = 0, Throwable $previous = NULL) {
    parent::__construct($message, $code, $previous);
  }
 
  public function __toString() {
    return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
  }
}
