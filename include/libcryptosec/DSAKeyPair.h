#ifndef DSAKEYPAIR_H_
#define DSAKEYPAIR_H_

#include <libcryptosec/KeyPair.h>

/**
* Representa um par de chaves assimétricas DSA.
 * Essa classe deve ser usada para a criação de chaves assimétricas DSA
 * É uma especialização da classe KeyPair
 * @ingroup AsymmetricKeys 
 */
 
class DSAKeyPair : public KeyPair
{
	public:
		/**
		 * create a DSAKeyPair object, creating a new key pair

		 * @param length key lenght
		 * @throws AsymmetricKeyException if the key cannot be created
		 */
		DSAKeyPair(int length);
		
		virtual ~DSAKeyPair();

		/**
		 * encode the key pair in PEM format encrypted
		 * @param passphrase key for encrypt the key pair
		 * @param mode cipher operation mode
		 * @return key pair encrypted encoded in PEM format
		 */

		virtual AsymmetricKey::Algorithm getAlgorithm() const;
};

#endif /*DSAKEYPAIR_H_*/
