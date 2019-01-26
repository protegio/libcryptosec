#ifndef CERTIFICATEREVOCATIONLIST_H_
#define CERTIFICATEREVOCATIONLIST_H_

#include <openssl/x509.h>

#include <string>
#include <vector>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/DateTime.h>
#include <libcryptosec/PublicKey.h>

#include "Extension.h"
#include "KeyUsageExtension.h"
#include "ExtendedKeyUsageExtension.h"
#include "BasicConstraintsExtension.h"
#include "CRLDistributionPointsExtension.h"
#include "AuthorityInformationAccessExtension.h"
#include "IssuerAlternativeNameExtension.h"
#include "SubjectAlternativeNameExtension.h"
#include "AuthorityKeyIdentifierExtension.h"
#include "SubjectKeyIdentifierExtension.h"
#include "SubjectInformationAccessExtension.h"
#include "CertificatePoliciesExtension.h"
#include "CRLNumberExtension.h"
#include "DeltaCRLIndicatorExtension.h"

#include "RDNSequence.h"
#include "RevokedCertificate.h"

class CertificateRevocationList
{
public:
	CertificateRevocationList(const X509_CRL *crl);
	CertificateRevocationList(X509_CRL *crl);
	CertificateRevocationList(std::string pemEncoded);
	CertificateRevocationList(ByteArray &derEncoded);
	CertificateRevocationList(const CertificateRevocationList& crl);
	virtual ~CertificateRevocationList();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	std::string getPemEncoded();
	ByteArray getDerEncoded();
	long getSerialNumber();
	BigInteger getSerialNumberBigInt();
	long getBaseCRLNumber();
	BigInteger getBaseCRLNumberBigInt();
	long getVersion();
	RDNSequence getIssuer();
	DateTime getLastUpdate();
	DateTime getNextUpdate();
	std::vector<RevokedCertificate> getRevokedCertificate();
	bool verify(const PublicKey& publicKey);
	X509_CRL* getX509Crl() const;
	CertificateRevocationList& operator =(const CertificateRevocationList& value);
	std::vector<Extension*> getExtension(Extension::Name extensionName);
	std::vector<Extension *> getExtensions();
	std::vector<Extension *> getUnknownExtensions();
protected:
	X509_CRL *crl;
};

#endif /*CERTIFICATEREVOCATIONLIST_H_*/
