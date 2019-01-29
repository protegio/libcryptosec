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
protected:
	Certificate(X509* cert);

public:
	Certificate(const X509* cert);
	Certificate(const std::string& pemEncoded);
	Certificate(const ByteArray& derEncoded);

	Certificate(const Certificate& cert);
	Certificate(Certificate&& cert);

	virtual ~Certificate();

	Certificate& operator=(const Certificate& cert);
	Certificate& operator=(Certificate&& cert);

	long getSerialNumber() const;
	BigInteger getSerialNumberBigInt() const;

	MessageDigest::Algorithm getMessageDigestAlgorithm() const;

	PublicKey getPublicKey() const;
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

	/**
	 * @brief Verifiy the certificate's signature.
	 *
	 * Only the signature is checked, no other verification is made.
	 *
	 * @param publicKey The public key to verify the signature.
	 */
	bool verify(const PublicKey& publicKey) const;

	/**
	 * @brief Create a new certificate request using the data from this certificate.
	 *
	 * @param privateKey The private key to sign the certificate request.
	 * @param algorithm The message digest algorithm to be used in the certificate
	 * 		request signature.
	 *
	 * @return The certificate request.
	 * @throws CertificationException If an error occurs on the conversion.
	 */
	CertificateRequest getNewCertificateRequest(const PrivateKey &privateKey, MessageDigest::Algorithm algorithm) const;

	bool operator==(const Certificate& value);
	bool operator!=(const Certificate& value);

	std::string getPemEncoded() const;
	ByteArray getDerEncoded() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string toXml(const std::string& tab = "") const;

	X509* getSslObject() const;
	const X509* getX509() const;

protected:
	X509 *cert;
};

#endif /*CERTIFICATE_H_*/
