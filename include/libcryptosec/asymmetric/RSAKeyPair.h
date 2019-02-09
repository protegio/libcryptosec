#ifndef RSAKEYPAIR_H_
#define RSAKEYPAIR_H_

#include <libcryptosec/asymmetric/KeyPair.h>

#include <libcryptosec/asymmetric/AsymmetricKey.h>

/**
 * Representa um par de chaves assimétricas RSA.
 *
 * Essa classe deve ser usada para a criação de chaves assimétricas RSA.
 *
 * @ingroup AsymmetricKeys 
 */
 
class RSAKeyPair : public KeyPair
{
	public:

		/**
		 * @brief Gera um par de chaves RSA.
		 *
		 * @param size O tamanho da chave em bits.
		 *
		 * @throws AsymmetricKeyException Se ocorrer um erro na geração da chave.
		 */
		RSAKeyPair(int size);

		/**
		 * @brief Destrutor padrão.
		 */
		virtual ~RSAKeyPair();

		/**
		 * @return Retorna AsymmetricKey::Algorithm::RSA.
		 */
		virtual AsymmetricKey::Algorithm getAlgorithm() const;
};

#endif /*RSAKEYPAIR_H_*/
