#ifndef REVOKEDCERTIFICATE_H_
#define REVOKEDCERTIFICATE_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <libcryptosec/DateTime.h>
#include <libcryptosec/Base64.h>

#include <libcryptosec/exception/CertificationException.h>

class RevokedCertificate
{
public:
	enum ReasonCode
	{
		UNSPECIFIED = 0,
		KEY_COMPROMISE = 1,
		CA_COMPROMISE = 2,
		AFFILIATION_CHANGED = 3,
		SUPER_SEDED = 4,
		CESSATION_OF_OPERATION = 5,
		CERTIFICATE_HOLD = 6,
		PRIVILEGE_WITH_DRAWN = 7,
		AACOMPROMISE = 8,
	};

	RevokedCertificate();
	RevokedCertificate(const X509_REVOKED *revoked);
	RevokedCertificate(const BigInteger& certificateSerialNumber, const DateTime& revocationDate, RevokedCertificate::ReasonCode reasonCode);

	virtual ~RevokedCertificate();
	
	void setCertificateSerialNumber(const BigInteger& certificateSerialNumber);
	const BigInteger& getCertificateSerialNumber() const;

	void setRevocationDate(const DateTime& revocationDate);
	const DateTime& getRevocationDate() const;

	void setReasonCode(const RevokedCertificate::ReasonCode reasonCode);
	RevokedCertificate::ReasonCode getReasonCode() const;

	X509_REVOKED* getSslObject() const;

	std::string toXml(const std::string& tab = "") const;

	static std::string reasonCode2Name(RevokedCertificate::ReasonCode reasonCode);

protected:
	BigInteger certificateSerialNumber;
	DateTime revocationDate;
	RevokedCertificate::ReasonCode reasonCode;
};

#endif /*REVOKEDCERTIFICATE_H_*/
