# php-bitcoin-signature-routines

PHP routines for verifying Cryptocurrency signatures. Requires PHP 5.3.2 with either GMP or BC Math.

At present, Bitcoin, Bitcoin Gold, and Zcash Base58 addresses are supported. Other addresses of the same format can be added through the addrInfo function fairly easily.

The isMessageSignatureValid function now returns a string with results rather than throwing errors. Possible results are:
  * `Valid` The Address matches the Message and Signature.
  * `Invalid` The Address does not match the Message and Signature.
  * `Invalid Address Length` The Decoded Address is not 20 bytes + Version Length (1 for most, 2 for Zcash).
  * `Invalid Address Checksum` The last four bytes of the Decoded Address are not equal to the first four bytes of a double-sha256 hash of the Decoded Address.
  * `Invalid Address` The Address Version is not supported.
  * `Invalid Signature` The Signature could not be Base64 decoded.
  * `Invalid Signature Length` The Decoded Signature was not 65 bytes long.
  * `Invalid Signature Flags` The Signature's Recovery Flags were either negative or greater than 7.
  * `Invalid Public Key` The attempt to determine the Public Key from the Message and Signature failed.
