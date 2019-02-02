#include <libcryptosec/certificate/RevokedCertificate.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

RevokedCertificate::RevokedCertificate() :
		reasonCode(RevokedCertificate::UNSPECIFIED)
{
}

RevokedCertificate::RevokedCertificate(const X509_REVOKED *revoked)
{
	THROW_DECODE_ERROR_IF(revoked == NULL);

	const ASN1_INTEGER *sslSerialNumber = X509_REVOKED_get0_serialNumber(revoked);
	THROW_DECODE_ERROR_IF(sslSerialNumber == NULL);
	this->certificateSerialNumber = BigInteger(sslSerialNumber);

	const ASN1_TIME * sslRevocationDate = X509_REVOKED_get0_revocationDate(revoked);
	THROW_DECODE_ERROR_IF(sslRevocationDate == NULL);
	this->revocationDate = DateTime(sslRevocationDate);

	// The reason code is optional
	ASN1_ENUMERATED *asn1Enumerated = (ASN1_ENUMERATED*) X509_REVOKED_get_ext_d2i(revoked, NID_crl_reason, NULL, NULL);
	if (asn1Enumerated != NULL) {
		this->reasonCode = (RevokedCertificate::ReasonCode) ASN1_ENUMERATED_get(asn1Enumerated);
		ASN1_ENUMERATED_free(asn1Enumerated);
	} else {
		this->reasonCode = RevokedCertificate::UNSPECIFIED;
	}
}

RevokedCertificate::RevokedCertificate(const BigInteger& certificateSerialNumber, const DateTime& revocationDate, RevokedCertificate::ReasonCode reasonCode) :
		certificateSerialNumber(certificateSerialNumber),
		revocationDate(revocationDate),
		reasonCode(reasonCode)
{
}

RevokedCertificate::~RevokedCertificate()
{
}

void RevokedCertificate::setCertificateSerialNumber(const BigInteger& certificateSerialNumber)
{
	this->certificateSerialNumber = BigInteger(certificateSerialNumber);
}

const BigInteger& RevokedCertificate::getCertificateSerialNumber() const
{
	return this->certificateSerialNumber;
}

void RevokedCertificate::setRevocationDate(const DateTime& revocationDate)
{
	this->revocationDate = revocationDate;
}

const DateTime& RevokedCertificate::getRevocationDate() const
{
	return this->revocationDate;
}

void RevokedCertificate::setReasonCode(RevokedCertificate::ReasonCode reasonCode)
{
	this->reasonCode = reasonCode;
}

RevokedCertificate::ReasonCode RevokedCertificate::getReasonCode() const
{
	return this->reasonCode;
}

X509_REVOKED* RevokedCertificate::getSslObject() const
{
	X509_REVOKED *ret = NULL;
	ASN1_INTEGER *sslSerialNumber = NULL;
	ASN1_TIME *sslRevocationDate = NULL;
	int rc = 0;
	
	ret = X509_REVOKED_new();
	THROW_ENCODE_ERROR_IF(ret == NULL);

	try {
		sslSerialNumber = this->certificateSerialNumber.getASN1Value();
	} catch (...) {
		X509_REVOKED_free(ret);
		throw;
	}

	rc = X509_REVOKED_set_serialNumber(ret, sslSerialNumber);
	ASN1_INTEGER_free(sslSerialNumber);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			X509_REVOKED_free(ret);
	);

	try {
		sslRevocationDate = this->revocationDate.getAsn1Time();
	} catch (...) {
		X509_REVOKED_free(ret);
		throw;
	}

	rc = X509_REVOKED_set_revocationDate(ret, sslRevocationDate);
	ASN1_TIME_free(sslRevocationDate);
	THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
			X509_REVOKED_free(ret);
	);

	if (this->reasonCode != RevokedCertificate::UNSPECIFIED) {
		ASN1_ENUMERATED *asn1Enumerated = ASN1_ENUMERATED_new();
		THROW_ENCODE_ERROR_AND_FREE_IF(asn1Enumerated == NULL,
				X509_REVOKED_free(ret);
		);

		rc = ASN1_ENUMERATED_set(asn1Enumerated, this->reasonCode);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				X509_REVOKED_free(ret);
				ASN1_ENUMERATED_free(asn1Enumerated);
		);

		rc = X509_REVOKED_add1_ext_i2d(ret, NID_crl_reason, asn1Enumerated, 0, 0);
		ASN1_ENUMERATED_free(asn1Enumerated);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				X509_REVOKED_free(ret);
		);
	}

	return ret;
}

std::string RevokedCertificate::toXml(const std::string& tab) const
{
	std::string ret = tab + "<revokedCertificate>\n";
		ret += tab + "\t<certificateSerialNumber>" + this->certificateSerialNumber.toDec() + "</certificateSerialNumber>\n";
		ret += tab + "\t<revocationDate>" + this->revocationDate.toXml() + "</revocationDate>\n";
		if (this->reasonCode != RevokedCertificate::UNSPECIFIED) {
			ret += tab + "\t<reason>" + RevokedCertificate::reasonCode2Name(this->reasonCode) + "</reason>\n";
		}
	ret += tab + "</revokedCertificate>\n";
	return ret;
}

std::string RevokedCertificate::reasonCode2Name(RevokedCertificate::ReasonCode reasonCode)
{
	std::string ret;
	switch (reasonCode)
	{
		case RevokedCertificate::UNSPECIFIED:
			ret = "unspecified";
			break;
		case RevokedCertificate::KEY_COMPROMISE:
			ret = "keyCompromise";
			break;
		case RevokedCertificate::CA_COMPROMISE:
			ret = "caCompromise";
			break;
	    case RevokedCertificate::AFFILIATION_CHANGED:
			ret = "affiliationChanged";
			break;
	    case RevokedCertificate::SUPER_SEDED:
			ret = "superSeded";
			break;
	    case RevokedCertificate::CESSATION_OF_OPERATION:
			ret = "cessationOfOperation";
			break;
	    case RevokedCertificate::CERTIFICATE_HOLD:
			ret = "certificateHold";
			break;
	    case RevokedCertificate::PRIVILEGE_WITH_DRAWN:
			ret = "privilegeWithDrawn";
			break;
	    case RevokedCertificate::AACOMPROMISE:
			ret = "aACompromise";
			break;
	}
	return ret;
}
