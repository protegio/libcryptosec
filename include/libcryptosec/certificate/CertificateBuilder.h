#ifndef CERTIFICATEBUILDER_H_
#define CERTIFICATEBUILDER_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <vector>
#include <string>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/PrivateKey.h>
#include <libcryptosec/PublicKey.h>

#include "Certificate.h"
#include "CertificateRequest.h"
#include "Extension.h"
#include "KeyUsageExtension.h"
#include "ExtendedKeyUsageExtension.h"
#include "BasicConstraintsExtension.h"
#include "CRLDistributionPointsExtension.h"
#include "IssuerAlternativeNameExtension.h"
#include "SubjectAlternativeNameExtension.h"
#include "SubjectInformationAccessExtension.h"
#include "AuthorityKeyIdentifierExtension.h"
#include "SubjectKeyIdentifierExtension.h"
#include "CertificatePoliciesExtension.h"

#include <libcryptosec/exception/AsymmetricKeyException.h>
#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/exception/EncodeException.h>

class CertificateBuilder
{
public:
	CertificateBuilder();
	CertificateBuilder(std::string pemEncoded);
	CertificateBuilder(ByteArray &derEncoded);
	CertificateBuilder(CertificateRequest &request);
	CertificateBuilder(const CertificateBuilder& cert);
	virtual ~CertificateBuilder();
	std::string getPemEncoded();
	ByteArray getDerEncoded();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string toXml(std::string tab = "");
	void setSerialNumber(long serial);
	/**
	 * Definir serial à partir de BigInteger, para seriais maiores do que um "long".
	 */
	void setSerialNumber(BigInteger serial);
	long getSerialNumber();
	BigInteger getSerialNumberBigInt();
	MessageDigest::Algorithm getMessageDigestAlgorithm();
	void setPublicKey(PublicKey &publicKey);
	PublicKey* getPublicKey();
	ByteArray getPublicKeyInfo();
	void setVersion(long version);
	long getVersion();
	void setNotBefore(DateTime &dateTime);
	DateTime getNotBefore();
	void setNotAfter(DateTime &dateTime);
	DateTime getNotAfter();

	/**
	 * Define o campo "issuer" a partir de um RDNSequence, utilizando o
	 * codificação de string padrão do OpenSSL.
	 *
	 * @param name issuer
	 */
	void setIssuer(RDNSequence &name);

	/**
	 * Define o campo "issuer" a partir de um X509, respeitando o
	 * codificação de string existente.
	 *
	 * @param issuer issuer
	 */
	void setIssuer(X509* issuer);

	RDNSequence getIssuer();

	/**
	 * Altera o campo "subject" a partir de um RDNSequence, respeitando a
	 * codificação de string existente.
	 *
	 * @param name subject
	 */
	void alterSubject(RDNSequence &name);

	/**
	 * Define o campo "subject" a partir de um RDNSequence, utilizando a
	 * codificação de string padrão do OpenSSL.
	 *
	 * @param name subject
	 */
	void setSubject(RDNSequence &name);

	/**
	 * Define o campo "subject" a partir de um X509_REQ, respeitando a
	 * codificação de string existente.
	 *
	 * @param name subject
	 */
	void setSubject(X509_REQ* req);
	RDNSequence getSubject();
	void addExtension(Extension &extension);
	void addExtensions(std::vector<Extension *> &extensions);
	void replaceExtension(Extension &extension);
	std::vector<Extension *> removeExtension(Extension::Name extensionName);
	std::vector<Extension *> removeExtension(ObjectIdentifier extOID);
	std::vector<Extension*> getExtension(Extension::Name extensionName);
	std::vector<Extension*> getExtensions();
	std::vector<Extension *> getUnknownExtensions();
	Certificate* sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm);
	X509* getX509() const;
	CertificateBuilder& operator =(const CertificateBuilder& value);
	bool isIncludeEcdsaParameters() const;
	void setIncludeEcdsaParameters(bool includeEcdsaParameters);
	void includeEcdsaParameters();

protected:
	X509 *cert;
	bool includeECDSAParameters;

private:
	int getCodification(RDNSequence& name);


};

#endif /*CERTIFICATEBUILDER_H_*/
