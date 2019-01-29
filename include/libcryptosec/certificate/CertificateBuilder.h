#ifndef CERTIFICATEBUILDER_H_
#define CERTIFICATEBUILDER_H_

#include <libcryptosec/certificate/Certificate.h>

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/MessageDigest.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <vector>
#include <string>

class BigInteger;
class ByteArray;
class CertificateRequest;
class DateTime;
class Extension;
class PublicKey;
class PrivateKey;
class RDNSequence;

class CertificateBuilder : public Certificate
{
public:
	CertificateBuilder();
	CertificateBuilder(const std::string& pemEncoded);
	CertificateBuilder(const ByteArray& derEncoded);
	CertificateBuilder(const CertificateRequest& request);

	CertificateBuilder(const CertificateBuilder& cert);
	CertificateBuilder(CertificateBuilder&& cert);

	virtual ~CertificateBuilder();

	CertificateBuilder& operator=(const CertificateBuilder& value);
	CertificateBuilder& operator=(CertificateBuilder&& builder);

	void setSerialNumber(long serial);
	void setSerialNumber(const BigInteger& serial);

	void setPublicKey(const PublicKey& publicKey);

	void setVersion(long version);

	void setNotBefore(const DateTime& dateTime);
	void setNotAfter(const DateTime& dateTime);

	/**
	 * Define o campo "issuer" a partir de um RDNSequence, utilizando o
	 * codificação de string padrão do OpenSSL.
	 *
	 * @param name issuer
	 */
	void setIssuer(const RDNSequence& name);

	/**
	 * Define o campo "issuer" a partir de um X509, respeitando o
	 * codificação de string existente.
	 *
	 * @param issuer issuer
	 */
	void setIssuer(X509* issuer);

	/**
	 * Altera o campo "subject" a partir de um RDNSequence, respeitando a
	 * codificação de string existente.
	 *
	 * @param name subject
	 */
	void alterSubject(const RDNSequence& name);

	/**
	 * Define o campo "subject" a partir de um RDNSequence, utilizando a
	 * codificação de string padrão do OpenSSL.
	 *
	 * @param name subject
	 */
	void setSubject(const RDNSequence& name);

	/**
	 * Define o campo "subject" a partir de um X509_REQ, respeitando a
	 * codificação de string existente.
	 *
	 * @param name subject
	 */
	void setSubject(X509_REQ* req);

	void addExtension(const Extension& extension);
	void addExtensions(const std::vector<Extension*>& extensions);
	void replaceExtension(const Extension& extension);
	std::vector<Extension*> removeExtension(Extension::Name extensionName);
	std::vector<Extension*> removeExtension(const ObjectIdentifier& extOID);

	bool isIncludeEcdsaParameters() const;
	void setIncludeEcdsaParameters(bool includeEcdsaParameters);
	void includeEcdsaParameters();

	Certificate sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm);

	const X509* getX509() const;

	std::string getXmlEncoded(const std::string& tab = "") const;
	std::string toXml(const std::string& tab = "") const;

protected:
	bool includeECDSAParameters;

private:
	int getCodification(const RDNSequence& name);


};

#endif /*CERTIFICATEBUILDER_H_*/
