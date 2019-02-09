#ifndef CERTIFICATEREVOCATIONLIST_H_
#define CERTIFICATEREVOCATIONLIST_H_

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/certificate/RevokedCertificate.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/asymmetric/PublicKey.h>
#include <libcryptosec/BigInteger.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/x509.h>

#include <string>
#include <vector>


class CertificateRevocationList
{
protected:
	CertificateRevocationList(X509_CRL* crl);

public:
	CertificateRevocationList(const X509_CRL* crl);
	CertificateRevocationList(const std::string& pemEncoded);
	CertificateRevocationList(const ByteArray& derEncoded);

	CertificateRevocationList(const CertificateRevocationList& crl);
	CertificateRevocationList(CertificateRevocationList&& crl);

	virtual ~CertificateRevocationList();

	CertificateRevocationList& operator=(const CertificateRevocationList& value);
	CertificateRevocationList& operator=(CertificateRevocationList&& value);

	BigInteger getSerialNumber() const;

	BigInteger getBaseCRLNumber() const;

	long getVersion() const;

	RDNSequence getIssuer() const;

	DateTime getLastUpdate() const;
	DateTime getNextUpdate() const;

	std::vector<RevokedCertificate> getRevokedCertificates() const;

	bool verify(const PublicKey& publicKey) const;

	std::vector<Extension*> getExtension(Extension::Name extensionName) const;
	std::vector<Extension*> getExtensions() const;
	std::vector<Extension*> getUnknownExtensions() const;

	std::string getPemEncoded() const;
	ByteArray getDerEncoded() const;

	std::string toXml(const std::string& tab = "") const;

	X509_CRL* getSslObject() const;
	const X509_CRL* getX509Crl() const;

protected:
	X509_CRL *crl;
};

#endif /*CERTIFICATEREVOCATIONLIST_H_*/
