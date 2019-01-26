#ifndef KEYPAIR_H_
#define KEYPAIR_H_

#include <libcryptosec/SymmetricCipher.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/AsymmetricKey.h>
#include <libcryptosec/Engine.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/evp.h>
#include <openssl/engine.h>

#include <string>

class Engine;

/**
 * Representa um par de chaves assimétricas. 
 * Essa classe deve ser usada para a criação de chaves assimétricas
 * bem como a condificação e decodificação do par para os formatos PEM e DER.
 * @ingroup AsymmetricKeys 
 */
 
class KeyPair
{
	public:
		/**
		 * create a KeyPair object, creating a new key pair
		 * @param algorithm key pair algorithm
		 * @param length key lenght
		 * @throws AsymmetricKeyException if the key cannot be created
		 */
		//TODO Este construtor deve é obsoleto. Devem ser usados os construtores das classes especializadas RSAKeyPair, DSAKeyPair e ECDSAKeyPair
		KeyPair(AsymmetricKey::Algorithm algorithm, int length);
		
		KeyPair(const Engine& engine, const std::string& keyId);

		/**
		 * create a KeyPair object, loading the key pair from encoded (PEM format), decrypting with key
		 * @param pemEncoded key pair encoded em PEM format
		 * @param passphrase passphrase to decrypt the key pair
		 */
		KeyPair(const std::string& pemEncoded, const ByteArray& passphrase);

		/**
		 * create a KeyPair object, loading the key pair from encoded (PEM format)
		 * @param pemEncoded key pair encoded em PEM format
		 */
		KeyPair(const std::string& pemEncoded);

		/**
		 * create a KeyPair object, loading the key pair from encoded (DER format)
		 * @param derEncoded key pair encoded em DER format
		 */
		KeyPair(const ByteArray& derEncoded);

		/**
		 * @brief Construtor de cópia.
		 *
		 * @param keyPair O par de chaves a ser copiada.
		 */
		KeyPair(const KeyPair& keyPair);

		/**
		 * @brief Construtor de move.
		 *
		 * @param keyPair O par de chaves a ser movido.
		 */
		KeyPair(KeyPair&& keyPair);

		/**
		 * @brief Destrutor padrão.
		 */
		virtual ~KeyPair();

		/**
		 * @brief Operador de atribuição por cópia.
		 *
		 * @param keyPair O par de chaves a ser copiado.
		 */
		KeyPair& operator=(const KeyPair& keyPair);

		/**
		 * @brief Operador de atribuição por movimentação.
		 *
		 * @param keyPair O par de chaves a ser movido.
		 */
		KeyPair& operator=(KeyPair&& keyPair);

		/**
		 * gets the public key from key pair
		 * @return a public key from key pair
		 */
		virtual PublicKey* getPublicKey() const;
		/**
		 * gets the private from key pair
		 * @return a private key from key pair
		 */
		virtual PrivateKey* getPrivateKey() const;
		/**
		 * encode the key pair in PEM format encrypted
		 * @param passphrase key for encrypt the key pair
		 * @param mode cipher operation mode
		 * @return key pair encrypted encoded in PEM format
		 */
		std::string getPemEncoded(const SymmetricKey& passphrase, SymmetricCipher::OperationMode mode) const;

		/**
		 * encode the key pair in PEM format
		 * @return key pair encoded in PEM format
		 */
		std::string getPemEncoded() const;

		/**
		 * encode the key pair in DER format
		 * @return key pair encoded in DER format
		 */
		ByteArray getDerEncoded() const;

		/**
		 * gets algorithm id from the key
		 * @return algorithm id
		 */
		virtual AsymmetricKey::Algorithm getAlgorithm() const;

		/**
		 * gets the key size
		 * @return key size
		 */
		int getSize() const;

		/**
		 * gets the key size in bits
		 * @return key size in bits
		 */
		int getSizeBits() const;
		
		const EVP_PKEY* getEvpPkey() const;

		const Engine& getEngine() const;

		const std::string& getKeyId() const;

	protected:
		KeyPair();
		static int passphraseCallBack(char *buf, int size, int rwflag, void *u);
		std::string getPublicKeyPemEncoded() const;
		std::string getPemEncoded(const EVP_CIPHER* cipher, const ByteArray* passphraseData) const;

		EVP_PKEY* key;		//< OpenSSL key abstraction
		std::string keyId;	//< Key id
		Engine engine;		//< OpenSSL key engine
};

#endif /*KEYPAIR_H_*/
