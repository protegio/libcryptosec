#ifndef CERTIFICATEREVOCATIONLISTBUILDER_H_
#define CERTIFICATEREVOCATIONLISTBUILDER_H_

#include <openssl/x509.h>

#include <string>
#include <vector>

#include <libcryptosec/DateTime.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/PrivateKey.h>

#include "CertificateRevocationList.h"
#include "RDNSequence.h"
#include "RevokedCertificate.h"

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

#include <libcryptosec/exception/AsymmetricKeyException.h>
#include <libcryptosec/exception/CertificationException.h>

class CertificateRevocationListBuilder
{
public:
	CertificateRevocationListBuilder();
	CertificateRevocationListBuilder(std::string pemEncoded);
	CertificateRevocationListBuilder(ByteArray &derEncoded);
	CertificateRevocationListBuilder(const CertificateRevocationListBuilder& crl);
	virtual ~CertificateRevocationListBuilder();
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	void setSerialNumber(long serial);
	/**
	 * Definir serial à partir de BigInteger, para seriais maiores do que um "long".
	 */
	void setSerialNumber(BigInteger serial);
	long getSerialNumber();
	BigInteger getSerialNumberBigInt();
	void setVersion(long version);
	long getVersion();
	void setIssuer(RDNSequence &issuer);
	void setIssuer(X509* issuer);
	RDNSequence getIssuer();
	void setLastUpdate(DateTime &dateTime);
	DateTime getLastUpdate();
	void setNextUpdate(DateTime &dateTime);
	DateTime getNextUpdate();
	void addRevokedCertificate(RevokedCertificate &revoked);
	void addRevokedCertificates(std::vector<RevokedCertificate> &revoked);
	std::vector<RevokedCertificate> getRevokedCertificate();
	CertificateRevocationList* sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigestAlgorithm);
	X509_CRL* getX509Crl() const;
	CertificateRevocationListBuilder& operator =(const CertificateRevocationListBuilder& value);
	void addExtension(Extension& extension);
	void addExtensions(std::vector<Extension *> &extensions);
	void replaceExtension(Extension &extension);
	std::vector<Extension*> getExtension(Extension::Name extensionName);
	std::vector<Extension*> getExtensions();
	std::vector<Extension *> getUnknownExtensions();

	
protected:
	X509_CRL *crl;
};

#endif /*CERTIFICATEREVOCATIONLISTBUILDER_H_*/
