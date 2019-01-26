#ifndef CERTIFICATEREVOCATIONLISTBUILDER_H_
#define CERTIFICATEREVOCATIONLISTBUILDER_H_

#include <libcryptosec/certificate/CertificateRevocationList.h>
#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/RevokedCertificate.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/BigInteger.h>

#include <openssl/x509.h>

#include <string>
#include <vector>

class ByteArray;
class PrivateKey;

class CertificateRevocationListBuilder
{
public:
	CertificateRevocationListBuilder();
	CertificateRevocationListBuilder(const std::string& pemEncoded);
	CertificateRevocationListBuilder(const ByteArray& derEncoded);
	CertificateRevocationListBuilder(const CertificateRevocationListBuilder& crlBuilder);
	CertificateRevocationListBuilder(CertificateRevocationListBuilder&& crlBuilder);

	virtual ~CertificateRevocationListBuilder();

	CertificateRevocationListBuilder& operator=(const CertificateRevocationListBuilder& crlBuilder);
	CertificateRevocationListBuilder& operator=(CertificateRevocationListBuilder&& crlBuilder);

	std::string getXmlEncoded(const std::string& tab = "") const;
	void setSerialNumber(long serial);
	void setSerialNumber(const BigInteger& serial);
	long getSerialNumber() const;
	BigInteger getSerialNumberBigInt() const;
	ASN1_INTEGER* getSerialNumberAsn1() const;

	void setVersion(long version);
	long getVersion() const;

	void setIssuer(const RDNSequence& issuer);
	void setIssuer(X509* issuer);
	RDNSequence getIssuer() const;

	void setLastUpdate(const DateTime& dateTime);
	DateTime getLastUpdate() const;

	void setNextUpdate(const DateTime& dateTime);
	DateTime getNextUpdate() const;

	void addRevokedCertificate(const RevokedCertificate& revoked);
	void addRevokedCertificates(const std::vector<RevokedCertificate>& revoked);
	std::vector<RevokedCertificate> getRevokedCertificates() const;

	CertificateRevocationList sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm);

	const X509_CRL* getX509Crl() const;

	void addExtension(const Extension& extension);
	void addExtensions(const std::vector<Extension*>& extensions);
	void replaceExtension(const Extension& extension);
	std::vector<Extension*> getExtension(Extension::Name extensionName) const;
	std::vector<Extension*> getExtensions() const;
	std::vector<Extension*> getUnknownExtensions() const;
	
protected:
	X509_CRL *crl;
};

#endif /*CERTIFICATEREVOCATIONLISTBUILDER_H_*/
