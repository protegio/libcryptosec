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

class CertificateRevocationListBuilder : public CertificateRevocationList
{
public:
	CertificateRevocationListBuilder();
	CertificateRevocationListBuilder(const std::string& pemEncoded);
	CertificateRevocationListBuilder(const ByteArray& derEncoded);

	virtual ~CertificateRevocationListBuilder();

	void setSerialNumber(long serial);
	void setSerialNumber(const BigInteger& serial);

	void setVersion(long version);

	void setIssuer(const RDNSequence& issuer);
	void setIssuer(const X509* issuer);

	void setLastUpdate(const DateTime& dateTime);

	void setNextUpdate(const DateTime& dateTime);

	void addRevokedCertificate(const RevokedCertificate& revoked);
	void addRevokedCertificates(const std::vector<RevokedCertificate>& revoked);

	CertificateRevocationList sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigestAlgorithm);

	void addExtension(const Extension& extension);
	void addExtensions(const std::vector<Extension*>& extensions);
	void replaceExtension(const Extension& extension);
};

#endif /*CERTIFICATEREVOCATIONLISTBUILDER_H_*/
