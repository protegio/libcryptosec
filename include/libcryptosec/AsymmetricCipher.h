#ifndef ASYMMETRICCIPHER_H_
#define ASYMMETRICCIPHER_H_

#include <libcryptosec/Macros.h>

#include <string>

class ByteArray;
class RSAPublicKey;
class RSAPrivateKey;

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
	 * @brief Encrypt binary data using a asymmetric public key.
	 *
	 * @param key		Public key to encrypt data.
	 * @param data		Data to be encrypted.
	 * @param padding	Type of padding to use in process.
	 *
	 * @return Encrypted data.
	 * @throws AsymmetricCipherException If any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray* encrypt(const RSAPublicKey& key, const ByteArray& data, AsymmetricCipher::Padding padding);

	/**
	 * @brief Encrypt string using a asymmetric public key.
	 *
	 * The null terminator (\0) is included in the encrypted data.
	 *
	 * @param key		Public key to encrypt data.
	 * @param data		Data to be encrypted.
	 * @param padding	Type of padding to use in process.
	 *
	 * @return Encrypted data.
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray* encrypt(const RSAPublicKey& key, const std::string& data, AsymmetricCipher::Padding padding);

	/**
	 * @brief Decrypt encrypted data using a asymmetric private key.
	 *
	 * @param key		Private key to decrypt encrypted data.
	 * @param data		Data to be decrypted.
	 * @param padding	Type of padding to use in process (must be the same used
	 * 						to perform the encrypting operation)
	 *
	 * @return Encrypted data.
	 * @throws AsymmetricCipherException if any problem happen, throw this exception with a ENCRYPTING_DATA code.
	 */
	static ByteArray* decrypt(const RSAPrivateKey& key, const ByteArray& data, AsymmetricCipher::Padding padding);

private:

	/**
	 * @brief Internal use. Used to convert the libcryptosec padding value to openssl padding value.
	 *
	 * @param padding Libcryptosec padding id.
	 *
	 * @return OpenSSL padding id.
	 */
	static int getPadding(AsymmetricCipher::Padding padding);
};

#endif /*ASYMMETRICCIPHER_H_*/
