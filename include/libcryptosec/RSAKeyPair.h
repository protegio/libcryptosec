#ifndef RSAKEYPAIR_H_
#define RSAKEYPAIR_H_

#include <libcryptosec/KeyPair.h>

#include <libcryptosec/AsymmetricKey.h>

/**
 * Representa um par de chaves assimétricas RSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas RSA
 * É uma especialização da classe KeyPair
 * @ingroup AsymmetricKeys 
 */
 
class RSAKeyPair : public KeyPair
{
	public:
		/**
		 * create a RSAKeyPair object, creating a new key pair

		 * @param length key lenght
		 * @throws AsymmetricKeyException if the key cannot be created
		 */
		RSAKeyPair(int length);
		
		virtual ~RSAKeyPair();

		/**
		 * encode the key pair in PEM format encrypted
		 * @param passphrase key for encrypt the key pair
		 * @param mode cipher operation mode
		 * @return key pair encrypted encoded in PEM format
		 */

		virtual AsymmetricKey::Algorithm getAlgorithm() const;
};

#endif /*RSAKEYPAIR_H_*/
