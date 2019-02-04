#ifndef PKCS7BUILDER_H_
#define PKCS7BUILDER_H_

#include <libcryptosec/pkcs7/Pkcs7.h>
#include <libcryptosec/certificate/CertificateRevocationList.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/SymmetricKey.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

#include <string>

/**
 * Implementa um contrutor de PKCS7, permitindo criar todos os tipos de PKCS7.
 * 
 * @ingroup PKCS7
 **/
class Pkcs7Builder
{
	
public:

	/**
	 * @brief Construtor padrão.
	 *
	 * Cria uma nova estrutura PKCS7.
	 **/	
	Pkcs7Builder();
	
	/**
	 * @brief Destrutor padrão.
	 *
	 * Limpa a estrutura PKCS7.
	 **/
	virtual ~Pkcs7Builder();

	/**
	 * @brief Inicializa o construtor de PKCS7 no modo DATA.
	 *
	 * No modo DATA o conteúdo é inserido em claro, sem assinatura e sem mecanismo
	 * de verificação de integridade, no PKCS7.
	 */
	void initData();

	/**
	 * @brief Inicializa o construtor de PKCS7 no modo DIGEST.
	 *
	 * No modo DIGEST o conteúdo é inserido em claro com mecanismo de
	 * verificação de integridade no PKCS7.
	 *
	 * @param messageDigestAlgorithm O algoritmo de hash a ser utilizado.
	 */
	void initDigest(MessageDigest::Algorithm messageDigestAlgorithm, bool attached);

	/**
	 * @brief Inicializa o construtor de PKCS7 no modo ENCRYTPED.
	 *
	 * No modo ENCRYPTED o conteúdo é inserido cifrado no PKCS7.
	 *
	 * Diferente do modo ENVELOPED, o modo ENCRYPTED não gerencia as
	 * chaves de cifração do PKCS7.
	 *
	 * @param
	 *
	 * @throw EncodeException
	 */
	void initEncrypted();

	/**
	 * @brief Inicializa o construtor de PKCS7 no modo SIGNED.
	 *
	 * No modo SIGNED o conteúdo em claro é assinado por todos signatários e
	 * as assinaturas incluídas no PKCS7. Se o parâmetro \p attached for true
	 * o conteúdo assinado também é inserido, em claro, no PKCS7.
	 *
	 * Para adicionar signatários é necessário utilizar a função addSigner().
	 *
	 * Se nenhum signatário for adicionado, o PKCS7 será gerado sem nenhuma assinatura,
	 * mas com todos certificados e CRLs adicionados com addCertificate() e addCrl().
	 *
	 * @param attached Define se o conteúdo assinado é anexado ou não no PKCS7.
	 *
	 * @see addSigner
	 * @see addCertificate
	 * @see addCrl
	 * @see update
	 * @see doFinal
	 */
	void initSigned(bool attached);

	/**
	 * @brief Inicializa o construtor de PKCS7 no modo ENVELOPED.
	 *
	 * No modo ENVELOPED o conteúdo é cifrado para todos destinatários. Diferente
	 * do modo ENCRYPTED, o modo ENVELOPED se responsabiliza por gerar a chave
	 * de cifração do conteúdo e cifrá-la para todos destinatários.
	 *
	 * Para adicionar destinatários é necessário chamar a função addRecipient().
	 *
	 * @param symmetricAlgorithm O algoritimo de cifração.
	 * @param operationMode O modo de operação da cifração.
	 *
	 * @throw EncodeException
	 *
	 * @see addRecipient
	 * @see update
	 * @see doFinal
	 */
	void initEnveloped(SymmetricKey::Algorithm symmetricAlgorithm,
			SymmetricCipher::OperationMode operationMode);

	/**
	 * @brief Inicializa o construtor de PKCS7 no modo ENVELOPED_AND_SIGNED.
	 *
	 * No modo ENVELOPED_AND_SIGNED o conteúdo em claro é assinado para todos
	 * signatários e as assinaturas incluídas no PKCS7. O conteúdo é cifrado
	 * para todos destinatários e incluído no PKCS7.
	 *
	 * Para adicionar signatários é necessário chamar a função addSigner().
	 * Para adicionar destinatários é necessário chamar a função addRecipient().
	 *
	 * @param symmetricAlgorithm O algoritimo de cifração.
	 * @param operationMode O modo de operação da cifração.
	 *
	 * @throw EncodeException
	 */
	void initEnvelopedAndSigned();

	/**
	 * @brief Add a certificate to the PKCS7.
	 *
	 * @param certificate The certificate to be added.
	 *
	 * @throw EncodeException
	 */
	void addCertificate(const Certificate& certificate);

	/**
	 * @brief Add a CRL to the PKCS7.
	 *
	 * @param crl The CRL to be added.
	 *
	 * @throw EncodeException
	 */
	void addCrl(const CertificateRevocationList& crl);

	/**
	 * @brief Add a signer to the PKCS7.
	 *
	 * The signer's certificate is automatically added in the PKCS7.
	 *
	 * @param messageDigestAlgorithm The message digest algorithm to be used in this signer's signature.
	 * @param signerCertificate The signer's certificate.
	 * @param signerPrivateKEy The signer's private key to perform the signature.
	 *
	 * @throw EncodeException
	 */
	void addSigner(MessageDigest::Algorithm messageDigestAlgorithm,
			const Certificate& signerCertificate, const PrivateKey& signerPrivateKey);

	/**
	 * @brief Add a recipient to the PKCS7.
	 *
	 * The recipient's certificate is automatically added to the PKCS7.
	 *
	 * The PKCS7 content will be enveloped to all recipients.
	 *
	 * @param recipientCertificate The recipient's certificate.
	 *
	 * @throw EncodeException
	 *
	 */
	void addRecipient(const Certificate& recipientCertificate);

	/**
	 * @brief Concatena novos dados ao pacote PKCS7.
	 *
	 * O terminador nulo (\0) da string também é concatenado.
	 *
	 * @param data Os dados a serem concatenados.
	 *
	 * @throw OperationException Caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(const std::string& data);
	
	/**
	 * @brief Concatena novos dados ao pacote PKCS7.
	 *
	 * @param data Os dados a serem concatenados.
	 *
	 * @throw OperationException Caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(const ByteArray& data);
	
	/**
	 * @brief Concatena novos dados ao pacote PKCS7.
	 *
	 * @param data Os dados a serem concatenados.
	 * @param size O numero de bytes a serem concatenados.
	 *
	 * @throw OperationException Caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(const unsigned char* data, unsigned int size);

	/**
	 * @brief Finaliza a construção do PKCS7 e retorna.
	 */
	Pkcs7 doFinal();

	/**
	 * @brief Concatena o conteúdo e finaliza a construção.
	 *
	 * O terminador nulo da string também é concatenado.
	 *
	 * @param data O conteúdo a ser concatenado.
	 *
	 * @return O PKCS7 contruído.
	 *
	 * @throw EncodeException
	 *
	 * @see update
	 * @see doFinal
	 */
	Pkcs7 doFinal(const std::string& data);

	/**
	 * @brief Concatena o conteúdo e finaliza a construção.
	 *
	 * @param data O conteúdo a ser concatenado.
	 *
	 * @return O PKCS7 contruído.
	 *
	 * @throw EncodeException
	 *
	 * @see update
	 * @see doFinal
	 */
	Pkcs7 doFinal(const ByteArray& data);

	/**
	 * @brief Concatena o conteúdo e finaliza a construção.
	 *
	 * @param data O ponteiro para o conteúdo a ser concatenado.
	 * @param size O número de bytes do conteúdo a ser concatenado.
	 *
	 * @return O PKCS7 contruído.
	 *
	 * @throw EncodeException
	 *
	 * @see update
	 * @see doFinal
	 */
	Pkcs7 doFinal(const unsigned char *data, unsigned int size);

	/**
	 * @brief Gera um pacote PKCS7 a partir de de um stream de entrada e escreve o
	 * pacote gerado no formato PEM em um stream de saída.
	 *
	 * @param in Stream de entrada de onde será lido o conteúdo que será adicionado ao pacote PKCS7.
	 * @param out Stream de saída onde será escrito o pacote PKCS7 no formato PEM.
	 *
	 * @throw OperationException caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void doFinal(std::istream* in, std::ostream* out);

	/**
	 * @brief Reinicia o estado do objeto.
	 *
	 * Todos buffer são limpos e o estado vai para NO_INIT.
	 */
	virtual void reset();

protected:

	/**
	 * @enum State
	 **/
	/**
	 *  Possíveis estados do builder. 
	 **/
	enum State
	{
		NO_INIT,	/*!< estado inicial, quando o builder ainda não foi inicializado.*/
		INIT,		/*!< estado em que o builder foi inicializado, mas ainda não recebeu dados para adicionar ao pacote PKCS7.*/
		UPDATE,		/*!< estado em que o builder já possui condições para finalizar a criação do pacote através da chamada Pkcs7Builder::doFinal().*/
	};
	
	/**
	 * Estrutura OpenSSL que representa o pacote PKCS7 
	 **/
	PKCS7 *pkcs7;
	
	/**
	 * Estrutura OpenSSL usada na geração do pacote PKCS7
	 **/
	BIO *p7bio;
	
	/**
	 * Estado atual do builder
	 **/
	Pkcs7Builder::State state;

	/**
	 * Modo de inicialização.
	 */
	Pkcs7::Type mode;
};

#endif /*PKCS7BUILDER_H_*/
