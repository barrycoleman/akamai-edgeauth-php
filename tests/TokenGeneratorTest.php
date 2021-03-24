<?php

use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
  public function testNormalInitializationWithEndTime()
  {
    $endTime = time() + 3600; 

    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['key'=>'abc123', 'endTime'=>$endTime]);
    $this->assertTrue(is_object($gen));

    $token = $gen->generateACLToken('/foo');
    $this->assertStringMatchesFormat('exp='.$endTime.'~acl=/foo~hmac=%x', $token);

    $token2 = $gen->generateURLToken('/foo');
    $this->assertStringMatchesFormat('exp='.$endTime.'~hmac=%x', $token2);
  }

  public function testNormalInitializationWithWindow()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['key'=>'abc123', 'windowSeconds'=> 3600]);
    $this->assertTrue(is_object($gen));

    $token = $gen->generateACLToken('/foo');

    $this->assertStringStartsWith('exp=', $token);
    $this->assertStringMatchesFormat('exp=%i~acl=/foo~hmac=%x', $token);
  }

  public function testKnownGoodValuesOfHmac()
  {
    $startTime = 1616545627;
    $endTime = 1616545657;

    $expectHmac = 'ba0d665ffc7c80159d08e1a9a143ed345bc2f3e374f8af73248ff67fb087a420';

    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['key'=>'abc123', 'startTime'=>$startTime, 'endTime'=>$endTime]);
    $this->assertTrue(is_object($gen));

    $token = $gen->generateACLToken('/foo');
    $this->assertStringMatchesFormat('st='.$startTime.'~exp='.$endTime.'~acl=/foo~hmac='.$expectHmac, $token);
  }

  public function testWithSha1()
  {
    $startTime = 1616545627;
    $endTime = 1616545657;

    $expectHmac = 'd0a1b5410049ecef4fcbd91ee4f53a7cda0084bc';

    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['algorithm'=>'sha1', 'key'=>'abc123', 'startTime'=>$startTime, 'endTime'=>$endTime]);
    $this->assertTrue(is_object($gen));

    $token = $gen->generateACLToken('/foo');
    $this->assertStringMatchesFormat('st='.$startTime.'~exp='.$endTime.'~acl=/foo~hmac='.$expectHmac, $token);
  }

  public function testWithMD5()
  {
    $startTime = 1616545627;
    $endTime = 1616545657;

    $expectHmac = '75f85046a2f91c1757d1a3efde786344';

    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['algorithm'=>'md5', 'key'=>'abc123', 'startTime'=>$startTime, 'endTime'=>$endTime]);
    $this->assertTrue(is_object($gen));

    $token = $gen->generateACLToken('/foo');
    $this->assertStringMatchesFormat('st='.$startTime.'~exp='.$endTime.'~acl=/foo~hmac='.$expectHmac, $token);
  }

  public function testWithACLArray()
  {
    $startTime = 1616545627;
    $endTime = 1616545657;

    $expectHmac = '90a2177d45e7817cf3f48f73eeff9a642df0369ba21c0dda38f44c719a94a4e0';

    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['algorithm'=>'sha256', 'key'=>'abc123', 'startTime'=>$startTime, 'endTime'=>$endTime]);
    $this->assertTrue(is_object($gen));

    $token = $gen->generateACLToken(['/foo','/goo']);
    $this->assertStringMatchesFormat('st='.$startTime.'~exp='.$endTime.'~acl=/foo!/goo~hmac='.$expectHmac, $token);
  }

  public function testWithPayloadAndEarlyEscape()
  {
    $startTime = 1616545627;
    $endTime = 1616545657;
    $payload = 'dfj~hk342\'35#%$#%';

    $expectHmac = '6324c13322262efa7d8a21020dd1c35413f5e2194918706bc351b3eead0afbc0';

    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['escapeEarly'=>true, 'payload'=>$payload, 'key'=>'abc123', 'startTime'=>$startTime, 'endTime'=>$endTime]);
    $this->assertTrue(is_object($gen));

    $token = $gen->generateACLToken('/foo');
    $this->assertStringMatchesFormat('st='.$startTime.'~exp='.$endTime.'~acl=/foo~data=dfj%7ehk342%2735%23%25%24%23%25~hmac='.$expectHmac, $token);
  }

  /**
   * @expectedException barrycoleman\AkamaiEdgeAuth\TokenGeneratorException
   */
  public function testBadInitializationNoArray()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator();
  }

  /**
   * @expectedException barrycoleman\AkamaiEdgeAuth\TokenGeneratorException
   */
  public function testBadInitializationEmptyArray()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator([]);
  }

  public function testBadInitializationMissingEndTime()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['key'=>'abc123']);
    $this->expectException(barrycoleman\AkamaiEdgeAuth\TokenGeneratorException::class);
    $this->expectExceptionMessage('You must provide endTime or windowSeconds');
    $gen->generateACLToken('/foo');
  }

  public function testMissingACL()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['key'=>'abc123']);
    $this->expectException(barrycoleman\AkamaiEdgeAuth\TokenGeneratorException::class);
    $this->expectExceptionMessage('You must provide an ACL');
    $gen->generateACLToken();
  }

  public function testMissingURL()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['key'=>'abc123']);
    $this->expectException(barrycoleman\AkamaiEdgeAuth\TokenGeneratorException::class);
    $this->expectExceptionMessage('You must provide a URL');
    $gen->generateURLToken();
  }

  public function testWithBadEncryptionAlgorithm()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['algorithm'=>'barry', 'key'=>'abc123', 'windowSeconds'=>3600]);
    $this->expectException(barrycoleman\AkamaiEdgeAuth\TokenGeneratorException::class);
    $this->expectExceptionMessage('Algorithm should be one of sha256, sha1 or md5');
    $gen->generateURLToken('/foo');
  }

  public function testWithBadACL()
  {
    $gen = new barrycoleman\AkamaiEdgeAuth\TokenGenerator(['key'=>'abc123', 'windowSeconds'=>3600]);
    $this->expectException(barrycoleman\AkamaiEdgeAuth\TokenGeneratorException::class);
    $this->expectExceptionMessage('ACL must be a string or array');
    $gen->generateACLToken(45345);
  }
}
