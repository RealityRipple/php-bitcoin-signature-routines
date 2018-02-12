<?php
 if (extension_loaded('gmp'))
  define('USE_EXT', 'GMP');
 else if(extension_loaded('bcmath') && !defined('USE_EXT'))
  define ('USE_EXT', 'BCMATH');
 else
  die('GMP or BC Math extensions required.');

 spl_autoload_register
 (
  function ($f)
  {
   $base = dirname(__FILE__)."/phpecc/";
   $interfaceFile = $base."classes/interface/".$f."Interface.php";
   if (file_exists($interfaceFile))
    require_once $interfaceFile;
   $classFile = $base."classes/".$f.".php";
   if (file_exists($classFile))
    require_once $classFile;
   $utilFile = $base."classes/util/".$f.".php";
   if (file_exists($utilFile))
    require_once $utilFile;
  }
 );

 require_once(dirname(__FILE__).'/bigint.php');

 function isMessageSignatureValid($address, $signature, $message)
 {
  if (USE_EXT == 'GMP')
  {
   $secp256k1   = new CurveFp('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', '0', '7');
   $secp256k1_G = new Point($secp256k1,
     '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
     '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
     '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  }
  else
  {
   $secp256k1   = new CurveFp('115792089237316195423570985008687907853269984665640564039457584007908834671663', '0', '7');
   $secp256k1_G = new Point($secp256k1,
     '55066263022277343669578718895168534326250603453777594175500187360389116729240',
     '32670510020758816978083085130507043184471273380659243275938904335757337482424',
     '115792089237316195423570985008687907852837564279074904382605163141518161494337');
  }
  $address = AddrTools::base58check_decode($address);
  if ($address === 'Checksum Mismatch')
   return 'Invalid Address Checksum';
  if ((strlen($address) < 21) || (strlen($address) > 22))
   return 'Invalid Address Length';
  list($coin, $preLen) = AddrTools::addrInfo($address);
  if ($coin === 'Null' || $preLen === 0)
   return 'Invalid Address';
  $magic   = "$coin Signed Message:\n";
  $addPre  = substr($address, 0, $preLen);
  $signature = base64_decode($signature, true);
  if ($signature === false)
   return 'Invalid Signature';
  if (strlen($signature) != 65)
   return 'Invalid Signature Length';
  $recoveryFlags = ord($signature[0]) - 27;
  if ($recoveryFlags < 0 || $recoveryFlags > 7)
   return 'Invalid Signature Flags';
  $isCompressed = ($recoveryFlags & 4) != 0;
  $msgMagic = AddrTools::numToVarIntString(strlen($magic)).$magic;
  $msgData = AddrTools::numToVarIntString(strlen($message)).$message;
  $messageHash = hash('sha256', hash('sha256', $msgMagic.$msgData, true), true);
  $pubkey = AddrTools::recoverPubKey(BigInt::bin2big(substr($signature, 1, 32)), BigInt::bin2big(substr($signature, 33, 32)), BigInt::bin2big($messageHash), $recoveryFlags, $secp256k1_G);
  if ($pubkey === false)
   return 'Invalid Public Key';
  $point = $pubkey->getPoint();
  if (!$isCompressed)
   $pubBinStr = "\x04".str_pad(BigInt::big2bin($point->getX()), 32, "\x00", STR_PAD_LEFT).str_pad(BigInt::big2bin($point->getY()), 32, "\x00", STR_PAD_LEFT);
  else
   $pubBinStr = (AddrTools::isBignumEven($point->getY()) ? "\x02" : "\x03").str_pad(BigInt::big2bin($point->getX()), 32, "\x00", STR_PAD_LEFT);
  $derivedAddress = $addPre.hash('ripemd160', hash('sha256', $pubBinStr, true), true);
  if ($address === $derivedAddress)
   return 'Valid';
  return 'Invalid';
 }
 
 class AddrTools
 {
  public static function addrInfo($rawAddr)
  {
   switch (ord($rawAddr[0]))
   {
    case 0:
    case 5:
    case 111:
    case 196:
     return array('Bitcoin', 1);
     break;
    case 23:
    case 38:
     return array('Bitcoin Gold', 1);
     break;
    case 28:
     switch (ord($rawAddr[1]))
     {
      case 37:
      case 184:
      case 186:
      case 189:
       return array('Zcash', 2);
       break;
     }
     break;
   }
   return array('Null', 0);
  }

  public static function isBignumEven($bnStr)
  {
   return (((int)$bnStr[strlen($bnStr)-1]) & 1) == 0;
  }

  public static function recoverPubKey($r, $s, $e, $recoveryFlags, $G)
  {
   $isYEven = ($recoveryFlags & 1) != 0;
   $isSecondKey = ($recoveryFlags & 2) != 0;
   $curve = $G->getCurve();
   $signature = new Signature($r, $s);
   static $p_over_four;
   if (!$p_over_four)
    $p_over_four = BigInt::div(BigInt::add($curve->getPrime(), 1), 4);
   if (!$isSecondKey)
    $x = $r;
   else
    $x = BigInt::add($r, $G->getOrder());
   $alpha = BigInt::mod(BigInt::add(BigInt::add(BigInt::pow($x, 3), BigInt::mul($curve->getA(), $x)), $curve->getB()), $curve->getPrime());
   $beta = NumberTheory::modular_exp($alpha, $p_over_four, $curve->getPrime());
   if (AddrTools::isBignumEven($beta) == $isYEven)
    $y = BigInt::sub($curve->getPrime(), $beta);
   else
    $y = $beta;
   $R = new Point($curve, $x, $y, $G->getOrder());
   $point_negate = function($p) { return new Point($p->curve, $p->x, BigInt::neg($p->y), $p->order); };
   $rInv = NumberTheory::inverse_mod($r, $G->getOrder());
   $eGNeg = $point_negate(Point::mul($e, $G));
   $Q = Point::mul($rInv, Point::add(Point::mul($s, $R), $eGNeg));
   $Qk = new PublicKey($G, $Q);
   if ($Qk->verifies($e, $signature))
    return $Qk;
   return false;
  }

  public static function convBase($numberInput, $fromBaseInput, $toBaseInput)
  {
   if ($fromBaseInput == $toBaseInput)
    return $numberInput;
   $fromBase = str_split($fromBaseInput,1);
   $toBase = str_split($toBaseInput,1);
   $number = str_split($numberInput,1);
   $fromLen=strlen($fromBaseInput);
   $toLen=strlen($toBaseInput);
   $numberLen=strlen($numberInput);
   $retval='';
   if ($toBaseInput == '0123456789')
   {
    $retval = 0;
    for ($i = 1;$i <= $numberLen; $i++)
     $retval = bcadd($retval, bcmul(array_search($number[$i-1], $fromBase),bcpow($fromLen,$numberLen-$i)));
    return $retval;
   }
   if ($fromBaseInput != '0123456789')
    $base10 = AddrTools::convBase($numberInput, $fromBaseInput, '0123456789');
   else
    $base10 = $numberInput;
   if ($base10<strlen($toBaseInput))
    return $toBase[$base10];
   while ($base10 != '0')
   {
    $retval = $toBase[bcmod($base10,$toLen)].$retval;
    $base10 = bcdiv($base10,$toLen,0);
   }
   return $retval;
  }

  public static function base58check_decode($str)
  {
   $sV = ltrim(strtr($str, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv'), '0');
   if (USE_EXT == 'GMP')
    $v = gmp_init($sV, 58);
   else
    $v = AddrTools::convBase($sV, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv', '0123456789');
   $v = BigInt::big2bin($v);
   for ($i = 0; $i < strlen($str); $i++)
   {
    if ($str[$i] != '1')
     break;
    $v = "\x00" . $v;
   }
   $checksum = substr($v, -4);
   $v = substr($v, 0, -4);
   $expCheckSum = substr(hash('sha256', hash('sha256', $v, true), true), 0, 4);
   if ($expCheckSum != $checksum)
    return 'Checksum Mismatch';
   return $v;
  }

  public static function numToVarIntString($i)
  {
   if ($i < 0)
    return chr(0);
   if ($i < 0xfd)
    return chr($i);
   if ($i <= 0xffff)
    return pack('Cv', 0xfd, $i);
   if ($i <= 0xffffffff)
    return pack('CV', 0xfe, $i);
   return pack('CV', 0xfe, 0xffffffff);
  }
 }
