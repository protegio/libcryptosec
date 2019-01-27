#ifndef EXTENSION_H_
#define EXTENSION_H_

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/x509.h>

#include <string>

class Extension
{
public:
	enum Name
	{
		UNKNOWN,
		KEY_USAGE,
		EXTENDED_KEY_USAGE,
		AUTHORITY_KEY_IDENTIFIER,
		CRL_DISTRIBUTION_POINTS,
		AUTHORITY_INFORMATION_ACCESS,
		BASIC_CONSTRAINTS,
		CERTIFICATE_POLICIES,
		ISSUER_ALTERNATIVE_NAME,
		SUBJECT_ALTERNATIVE_NAME,
		SUBJECT_INFORMATION_ACCESS,
		SUBJECT_KEY_IDENTIFIER,
		CRL_NUMBER,
		DELTA_CRL_INDICATOR
	};
	
	/**
	 * @brief Inicializa a extensão a partir uma estrutura X509_EXTENSION.
	 *
	 * @param ext A estrutura X509_EXTENSION para ser usada na construção.
	 */
	Extension(const X509_EXTENSION *ext);

	/**
	 * @brief Inicializa a extensão a partir dos campos passados.
	 *
	 * @param oid O OID da extensão.
	 * @param critical Identifica se a extensão deve ser marcada como crítica ou não.
	 * @param valueBase64 O valor da extensão codificado em base 64.
	 */
	Extension(const std::string& oid, bool critical, const std::string& valueBase64);

	/**
	 * @brief Destrutor padrão.
	 */
	virtual ~Extension();
	
	/**
	 * @return Retorna o OID da extensão.
	 */
	const ObjectIdentifier& getObjectIdentifier() const;

	/**
	 * @return Retorna o valor da extensão;
	 */
	const ByteArray& getValue() const;

	/**
	 * @return O valor da extensão codificado em base64.
	 */
	std::string getBase64Value() const;

	/**
	 * @brief Define a criticidade da extensão.
	 *
	 * @param critical true para crítica, false par não crítica.
	 */
	void setCritical(bool critical);

	/**
	 * @return Se a extensão é crítica ou não.
	 */
	bool isCritical() const;

	/**
	 * @brief Retorna o nome da extensão.
	 *
	 * Retorna 'undefined' se for uma extensão desconhecida.
	 *
	 * @return O nome da extensão.
	 */
	std::string getNameString() const;

	/**
	 * @brief Retorna o identificador da extensão.
	 *
	 * Retorna 'Extension::UNKNOWN' se for uma extensão desconhecida.
	 *
	 * @return O identificador da extensão.
	 */
	Extension::Name getName() const;

	/**
	 * @brief Retorna a extensão codificada em XML.
	 *
	 * @param tab A string para ser usada como identação do XML.
	 * @return A string XML.
	 */
	std::string toXml(const std::string& tab = "") const;

	/**
	 * @brief Retorna o valor da extensão codificada em XML.
	 *
	 * Classes que extendem Extension podem implementar essa
	 * função para tornar o valor da extensão legível no XML
	 * retornado pela função toXML().
	 *
	 * @param tab A string para ser usada como identação do XML.
	 * @return A string XML.
	 */
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	/**
	 * @brief Constrói uma estutura X509_EXTENSION baseada na extensão.
	 *
	 * A extensão precisa ser desalocada por quem chamou a função.
	 *
	 * @return A estrutura X509_EXTENSION construída.
	 * @throw CertificationException Se houver algum erro na construção da
	 * 	estrutura X509_EXTENSION.
	 */
	virtual X509_EXTENSION* getX509Extension() const;

	/**
	 * @return O identificador de extensão correspondente ao nid passado.
	 */
	static Extension::Name getName(int nid);

	/**
	 * @return O identificador de extensão correspondente à extensão passada.
	 */
	static Extension::Name getName(const X509_EXTENSION *ext);

protected:
	/**
	 * @param Construtor padrão protegido.
	 */
	Extension();

	ObjectIdentifier objectIdentifier;	// O OID da extensão
	bool critical;						// A criticidade da extensão
	ByteArray value;					// O valor da extensão
};

#define THROW_EXTENSION_ENCODE_IF(exp)\
do {\
	if ((exp)) {\
		THROW(CertificationException, CertificationException::ENCODE_ERROR);\
	}\
} while(false)

#define THROW_EXTENSION_ENCODE_AND_FREE_IF(exp, to_free)\
do {\
	if ((exp)) {\
		to_free\
		THROW(CertificationException, CertificationException::ENCODE_ERROR);\
	}\
} while(false)

#define THROW_EXTENSION_DECODE_IF(exp)\
do {\
	if ((exp)) {\
		THROW(CertificationException, CertificationException::DECODE_ERROR);\
	}\
} while(false)

#define THROW_EXTENSION_DECODE_AND_FREE_IF(exp, to_free)\
do {\
	if ((exp)) {\
		to_free\
		THROW(CertificationException, CertificationException::DECODE_ERROR);\
	}\
} while(false)

#endif /*EXTENSION_H_*/
