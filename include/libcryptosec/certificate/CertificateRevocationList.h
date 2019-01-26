#ifndef CERTIFICATEREVOCATIONLIST_H_
#define CERTIFICATEREVOCATIONLIST_H_

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/certificate/RevokedCertificate.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/PublicKey.h>
#include <libcryptosec/BigInteger.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/x509.h>

#include <string>
#include <vector>


class CertificateRevocationList
{
public:
	CertificateRevocationList(const X509_CRL* crl);
	CertificateRevocationList(X509_CRL* crl);
	CertificateRevocationList(const std::string& pemEncoded);
	CertificateRevocationList(const ByteArray& derEncoded);

	CertificateRevocationList(const CertificateRevocationList& crl);
	CertificateRevocationList(CertificateRevocationList&& crl);

	virtual ~CertificateRevocationList();

	CertificateRevocationList& operator=(const CertificateRevocationList& value);
	CertificateRevocationList& operator=(CertificateRevocationList&& value);

	std::string getXmlEncoded(const std::string& tab = "") const;

	std::string getPemEncoded() const;
	ByteArray getDerEncoded() const;

	long getSerialNumber() const;
	BigInteger getSerialNumberBigInt() const;

	long getBaseCRLNumber() const;
	BigInteger getBaseCRLNumberBigInt() const;

	long getVersion() const;

	RDNSequence getIssuer() const;

	DateTime getLastUpdate() const;
	DateTime getNextUpdate() const;

	std::vector<RevokedCertificate> getRevokedCertificates() const;

	bool verify(const PublicKey& publicKey) const;

	X509_CRL* getX509Crl() const;

	std::vector<Extension*> getExtension(Extension::Name extensionName) const;
	std::vector<Extension*> getExtensions() const;
	std::vector<Extension*> getUnknownExtensions() const;

protected:
	X509_CRL *crl;
};

#endif /*CERTIFICATEREVOCATIONLIST_H_*/
