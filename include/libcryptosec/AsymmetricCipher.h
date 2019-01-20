#ifndef ASYMMETRICCIPHER_H_
#define ASYMMETRICCIPHER_H_

/* OpenSSL includes */

#include <openssl/evp.h>

/* local includes */
#include "ByteArray.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"

/* exceptions includes */
#include <libcryptosec/exception/AsymmetricCipherException.h>

/**
 * @ingroup Util 
 */

/**
 * @brief static class to perform asymmetric ciphers, using asymmetric keys (eg. RSA keys)
 * TODO: não deveria funcionar com outras chaves além de RSA? (e.g.: ECIES)
 */
class AsymmetricCipher
{
public:

	/**
	 * supported padding values to perform asymmetric ciphers. Default: PKCS1.
	 */
	DECLARE_ENUM( Padding, 3,
		NO_PADDING,
		PKCS1,
		PKCS1_OAEP
	);

	/**
	 * encrypt unreadable data using a asymmetric public key
	 * @param key public key to encrypt data
	 * @param data data to be encrypted
	 * @padding type of padding to use in process
	 * @return encrypted data
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray encrypt(RSAPublicKey &key, const ByteArray &data, AsymmetricCipher::Padding padding);

	/**
	 * encrypt readable data using a asymmetric public key
	 * @param key public key to encrypt data
	 * @param data data to be encrypted
	 * @padding type of padding to use in process
	 * @return encrypted data
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray encrypt(RSAPublicKey &key, const std::string &data, AsymmetricCipher::Padding padding);

	/**
	 * decrypt encrypted data using a asymmetric private key
	 * @param key private key to decrypt encrypted data
	 * @param data data to be decrypted
	 * @padding type of padding to use in process (must be the same used to perform the encrypting operation
	 * @return encrypted data
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray decrypt(RSAPrivateKey &key, const ByteArray &data, AsymmetricCipher::Padding padding);

private:

	/**
	 * Internal use. Used to convert the libcryptosec padding value to openssl padding value.
	 * @param libcryptosec padding value
	 * @return openssl padding value
	 */
	static int getPadding(AsymmetricCipher::Padding padding);
};

#endif /*ASYMMETRICCIPHER_H_*/
