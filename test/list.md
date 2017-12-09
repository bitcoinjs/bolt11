# List of tests

## Encode

* coinType
  * undefined coinType sets as testnet
  * unknown coinType throws error (Unknown coin type)
* payment hash
  * missing payment hash throws error (Lightning Payment Request needs a payment hash)
  * payment hash is not correct size or data type throws error
* description
  * missing description or purpose commit will throw error (Lightning Payment Request needs a description or a purpose commit hash (or message))
* payeeNodeKey
  * if payeeNodeKey and tag payee node key do not match throws error (payeeNodeKey and tag payee node key do not match)
* privateKey
  * without private key or signature data throws error (Lightning Payment Request needs signature data OR privateKey buffer)
  * private key wrong length or too large throws error (The private key given is not valid for SECP256K1)
  * if private key doesn't match payee node key tag, throws error (The private key given is not the private key of the node public key given)
* fallback address
  * bech32 address with unknown witness version throws error (Fallback address witness version is unknown)
  * bech32 prefix doesn't match network prefix throws error (Fallback address network type does not match payment request network type)
  * if base58 address version doesn't match P2PKH or P2SH of network, throws error (Fallback address version (base58) is unknown or the network type is incorrect)
  * if bech32 and base58 both fail, throws error (Fallback address type is unknown)
* routing info
  * if missing info throws error (Routing info is incomplete)
  * if route pubkey is not valid pubkey throws error (Routing info pubkey is not a valid pubkey)
  * if short channel id is not right length throws error (Routing info short channel id must be 8 bytes)
  * mSats is not an integer throws error (Routing info fee is not an integer)
  * cltvExpiryDelta is not an integer throws error (Routing info cltv expiry delta is not an integer)
* tags
  * unknown tag name throws error (Unknown tag key:)
* signature
  * payee node key tag doesn't match the recovered pulic key (data corruption) throws error (Signature, message, and recoveryID did not produce the same pubkey as payeeNodeKey)
  * signature only encoding when you don't have a payeeNodekey OR a payee node key tag throws error (Reconstruction with signature and recoveryID requires payeeNodeKey to verify correctness of input data.)

## Decode

* prefix
  * Doesn't start with `ln` should throw error (Not a proper lightning payment request)
  * missing cointype throws error (Not a proper lightning payment request)
  * multiplier isn't in [munp], throws error (Unknown multiplier used in amount)
* signature
  * recoveryID is not between 0-3 or signature is not 64 bytes throws error (Signature is missing or incorrect)
  * recovered pubkey does not match node key tag throws error (Lightning Payment Request signature pubkey does not match payee pubkey)
