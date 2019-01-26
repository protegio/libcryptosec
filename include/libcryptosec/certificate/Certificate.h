#ifndef CERTIFICATE_H_
#define CERTIFICATE_H_

#include <libcryptosec/certificate/CertificateRequest.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/BigInteger.h>

#include <openssl/x509.h>

#include <string>
#include <vector>

class PublicKey;
class PrivateKey;
class Extension;

class Certificate
{
public:
	Certificate(X509* cert);
	Certificate(const X509* cert);
	Certificate(const std::string& pemEncoded);
	Certificate(const ByteArray& derEncoded);
	Certificate(const Certificate& cert);
	Certificate(Certificate&& cert);

	virtual ~Certificate();

	Certificate& operator=(const Certificate& cert);
	Certificate& operator=(Certificate&& cert);

	std::string getPemEncoded() const;
	ByteArray getDerEncoded() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string toXml(const std::string& tab = "") const;

	long getSerialNumber() const;
	BigInteger getSerialNumberBigInt() const;
	MessageDigest::Algorithm getMessageDigestAlgorithm() const;
	PublicKey* getPublicKey() const;
	ByteArray getPublicKeyInfo() const;
	long getVersion() const;
	DateTime getNotBefore() const;
	DateTime getNotAfter() const;
	RDNSequence getIssuer() const;
	RDNSequence getSubject() const;
	std::vector<Extension*> getExtension(Extension::Name extensionName) const;
	std::vector<Extension*> getExtensions() const;
	std::vector<Extension*> getUnknownExtensions() const;
	ByteArray getFingerPrint(MessageDigest::Algorithm algorithm) const;
	bool verify(const PublicKey& publicKey) const;
	X509* getX509() const;

	/**
	 * create a new certificate request using the data from this certificate
	 * @param privateKey certificate request signing key
	 * @param algorithm message digest algorithm
	 * @throws CertificationException error on conversion of x509 to x509 req
	 */
	CertificateRequest getNewCertificateRequest(const PrivateKey &privateKey, MessageDigest::Algorithm algorithm) const;

	bool operator ==(const Certificate& value);
	bool operator !=(const Certificate& value);

protected:
	X509 *cert;
};

#endif /*CERTIFICATE_H_*/
