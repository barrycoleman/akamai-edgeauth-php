# akamai-edgeauth-php : Akamai Edge Authorization Token for PHP

akamai-edgeauth-php is a token generator for use with Akamai Edge AuthorizationToken in 
an HTTP cookie, query string or HTTP header. You can configure it in the Property Manager
at https://control.akamai.com. It is used by the behaviors `Auth Token 2.0 Verification` and
`Segmented Media Protection`.

akamai-edgeauth-php supports PHP 7.1+ and depends on hash_hmac() in PHP only.

![Akamai Property Manager image](https://github.com/AstinCHOI/akamai-asset/blob/master/edgeauth/edgeauth.png?raw=true)

## Installation

To install akamai-edgeauth-php with composer:

```shell
$ composer require barrycoleman/akamai-edgeauth-php
```

## Example

```PHP
<?php

require 'vendor/autoload.php';

$generator = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(
    [ 'key' => 'abc123', 'windowSeconds' => 3600 ]);
    
echo $generator->generateACLToken('/foo/*');
echo $generator->generateURLToken('/foo/index.html');
```

## Usage

#### TokenGenerator class

The constructor takes an array of parameters as key/value pairs

| Parameter | Description |
|-----------|-------------|
| key | (required) The encryption key to use. This should be the same value as you enter in the Akamai behavior Auth Token 2.0 Verification. Must be an even length hexadecimal digit string. |
| startTime | (optional) The unix time the token is valid from. This will default to the current time. Valid values are any integer greater than zero, and the string 'now'. |
| endTime | (optional) The unix time the token is valid until. This can be any time after the start time. This must be provided if 'windowSeconds' is not provided. |
| windowSeconds | (optional) The number of seconds the token should be valid for from the start time. This must be provided if 'endTime' is not provided. 'endTime' has priority over 'windowSeconds' if both are provided. |
| algorithm | (optional) The algorithm to use to create the token. Must be one of 'sha256', 'sha1', or 'md5'. Default is 'sha256'. |
| escapeEarly | (optional) Whether to escape strings before generation of the token. Default is false. |
| fieldDelimiter | (optional) The character to place between fields in the token. Default is '~'. If you intend the token to work in Akamai Auth Token 2.0 Verification behavior you should not change this. |
| aclDelimiter | (optional) The character to place between entries in an ACL array. Defailt is '!'. If you intend the token to work in Akamai Auth Token 2.0 Verification behavior you should not change this. |
| verbose | (optional) Will print out (using echo) the configuration of the component during token generation. Default is false. |
| ip | (optional) Used for specifying IP address. Uses escapeEarly if set true. |
| sessionId | (optional) Used for specifying a session id. Uses escapeEarly if set true. |
| payload | (optional) Used for specifying a payload. Uses escapeEarly if set true. |
| salt | (optional) Salt added to the token hash. This is deprecated in Akamai and should not be used for new implementations. |
| tokenName | (optional) This is unused in the current implementation. This would be the name of the cookie, query parameter or header to use. Default is '__token__'. |

#### TokenGenerator methods

```PHP
generateACLToken(acl)
generateURLToken(url)
```

| Parameter | Description |
|-----------|-------------|
| url | Single URL path (string) |
| acl | Access Control List can use the wildcards (\*, ?). It can be a single string or an array of strings. |

