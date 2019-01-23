#ifndef ASYMMETRICKEY_H_
#define ASYMMETRICKEY_H_

#include <openssl/evp.h>

#include <string>

class ByteArray;

/**
 * @defgroup AsymmetricKeys Classes relacionadas ao uso de chaves assimétricas.
 **/

/**
 * Classe que representa uma chave assimétrica.
 * 
 * Esta classe é abstrata e implementa apenas os procedimentos comuns a todos os tipos 
 * de chaves assimétricas.
 * @see PrivateKey
 * @see PublicKey
 * @see RSAPrivateKey
 * @see RSAPublicKey
 * @see DSAPrivateKey
 * @see DSAPublicKey
 * @see KeyPair
 * @ingroup AsymmetricKeys
 */
class AsymmetricKey 
{

public:
	
	/**
	 * @enum Algorithm
	 **/
	/**
	 *  Algoritmos assimétricos suportados.
	 **/		 
	enum Algorithm 
	{
		RSA,	/*!< A chave é do tipo RSA */
		DSA,	/*!< A chave é do tipo DSA */
		EC,		/*!< A chave é do tipo ECDSA */
	};

	/**
	 * @enum Curve
	 *
	 * Curvas Elipticas suportadas (= NID)
	 **/
	enum Curve
	{
		X962_PRIME192V1 = 409,
		X962_PRIME192V2 = 410,
		X962_PRIME192V3 = 411,
		X962_PRIME239V1 = 412,
		X962_PRIME239V2 = 413,
		X962_PRIME239V3 = 414,
		X962_PRIME256V1 = 415,
		X962_C2PNB163V1 = 684,
		X962_C2PNB163V2 = 685,
		X962_C2PNB163V3 = 686,
		X962_C2PNB176V1 = 687,
		X962_C2TNB191V1 = 688,
		X962_C2TNB191V2 = 689,
		X962_C2TNB191V3 = 690,
		X962_C2PNB208W1 = 693,
		X962_C2TNB239V1 = 694,
		X962_C2TNB239V2 = 695,
		X962_C2TNB239V3 = 696,
		X962_C2PNB272W1 = 699,
		X962_C2PNB304W1 = 700,
		X962_C2TNB359V1 = 701,
		X962_C2PNB368W1 = 702,
		X962_C2TNB431R1 = 703,

		SECG_SECP160K1 = 708,
		SECG_SECP160R1 = 709,
		SECG_SECP160R2 = 710,
		SECG_SECP192K1 = 711,
		SECG_SECP224K1 = 712,
		SECG_SECP256K1 = 714,
		SECG_SECT163R1 = 722,
		SECG_SECT193R1 = 724,
		SECG_SECT193R2 = 725,
		SECG_SECT239K1 = 728,

		NISTSECG_SECP224R1 = 713,
		NISTSECG_SECP384R1 = 715,
		NISTSECG_SECP521R1 = 716,
		NISTSECG_SECT163K1 = 721,
		NISTSECG_SECT163R2 = 723,
		NISTSECG_SECT233K1 = 726,
		NISTSECG_SECT233R1 = 727,
		NISTSECG_SECT283K1 = 729,
		NISTSECG_SECT283R1 = 730,
		NISTSECG_SECT409K1 = 731,
		NISTSECG_SECT409R1 = 732,
		NISTSECG_SECT571K1 = 733,
		NISTSECG_SECT571R1 = 734,

		BRAINPOOL_P160R1 = 921,
		BRAINPOOL_P160T1 = 922,
		BRAINPOOL_P192R1 = 923,
		BRAINPOOL_P192T1 = 924,
		BRAINPOOL_P224R1 = 925,
		BRAINPOOL_P224T1 = 926,
		BRAINPOOL_P256R1 = 927,
		BRAINPOOL_P256T1 = 928,
		BRAINPOOL_P320R1 = 929,
		BRAINPOOL_P320T1 = 930,
		BRAINPOOL_P384R1 = 931,
		BRAINPOOL_P384T1 = 932,
		BRAINPOOL_P512R1 = 933,
		BRAINPOOL_P512T1 = 934,
	};

	/**
	 * @brief Construtor de inicializaão da estrutura OpenSSL EVP_PKEY.
	 *
	 * Esse construtor deve ser usando apenas internamente. Para construir uma chave
	 * assimétrica nova deve ser utilizada a classe KeyPair.
	 *
	 * @param evpPkey O ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @throw AsymmetricKeyException Caso a estrutura EVP_PKEY não seja uma estrutura
	 * 	OpenSSL válida ou ocorra algum problema na sua carga.
	 */
	AsymmetricKey(EVP_PKEY* evpPkey);

	/**
	 * @brief Carrega uma chave assimétrica a partir da sua equivalente codificada em DER.
	 *
	 * Esse construtor deve ser implementado pelas subclasses.
	 *
	 * @param encoded A chave assimétrica no formato DER.
	 */
	AsymmetricKey(const ByteArray& encoded);
	
	/**
	 * @brief Carrega uma chave assimétrica a partir da sua equivalente codificada em PEM.
	 *
	 * Esse construtor deve ser implementado pelas subclasses.
	 *
	 * @param encoded A chave assimétrica no formato PEM.
	 */
	AsymmetricKey(const std::string& encoded);
	
	/**
	 * @brief Destrutor padrão.
	 *
	 * Desaloca a estrutura interna EVP_PKEY
	 */
	virtual ~AsymmetricKey();

	/**
	 * @brief Retorna a estrutura OpenSSL interna.
	 *
	 * @return Um ponteiro para a estrutura OpenSSL interna à classe AsymmetricKey.
	 */
	EVP_PKEY* getEvpPkey();

	/**
	 * @brief Retorna o algoritmo assimétrico que deve ser usado com a chave atual.
	 *
	 * @return O tipo do algoritmo simetrico para essa chave.
	 * @throw AsymmetricKeyException Caso o tipo de chave não tenha sido reconhecido.
	 * @see AsymmetricKey::Algorithm
	 */
	AsymmetricKey::Algorithm getAlgorithm();
			
	/**
	 * @brief Retorna o tamanho da chave em bytes.
	 *
	 * @return O tamanho da chave em bytes.
	 * @throw AsymmetricKeyException Se o tipo de chave não for suportado ou caso um
	 * erro tenha ocorrido ao tentar obter o tamanho da mesma.
	 */
	int getSize();
	
	/**
	 * @brief Retorna o tamanho da chave em bits.
	 *
	 * @return Tamanho da chave em bits.
	 * @throw AsymmetricKeyException Se o tipo de chave não for suportado ou caso um
	 * erro tenha ocorrido ao tentar obter o tamanho da mesma.
	 */
	int getSizeBits();
	
	/**
	 * @brief Verifica se a chave é igual à passada como argumento.
	 */
	bool operator==(AsymmetricKey& key) throw();

	/**
	 * @brief Retorna uma representação da chave codificada em DER.
	 *
	 * @return A chave assimétrica no formato DER.
	 */
	virtual ByteArray* getDerEncoded() = 0;

	/**
	 * @brief Retorna uma representação da chave codificada em PEM.
	 *
	 * @return A chave assimétrica no formato PEM.
	 */
	virtual std::string getPemEncoded() = 0;

protected:
	
	/**
	 * @brief Construtor padrão;
	 *
	 * Inicializa a estrutura EVP_PKEY como NULL.
	 */
	AsymmetricKey();

	/**
	 * @brief Define a estrutura EVP_PKEY.
	 *
	 * Essa função desaloca a referência anterior.
	 *
	 * @param evpPkey A estrutura EVP_PKEY.
	 */
	void setEvpPkey(EVP_PKEY* evpPkey);

protected:

	/**
	 * Ponteiro para a estrutura interna OpenSSL EVP_PKEY.
	 */
	EVP_PKEY *evpPkey;
};

#endif /*ASYMMETRICKEY_H_*/
