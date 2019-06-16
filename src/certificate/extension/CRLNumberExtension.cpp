#include <libcryptosec/certificate/extension/CRLNumberExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

#include <openssl/x509v3.h>
#include <openssl/asn1.h>

CRLNumberExtension::CRLNumberExtension(const BigInteger& serial) :
		Extension(), serial(serial)
{
    this->objectIdentifier = ObjectIdentifier::fromNid(NID_crl_number);
}

CRLNumberExtension::CRLNumberExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::CRL_NUMBER);

	ASN1_INTEGER *sslObject = (ASN1_INTEGER*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	try {
		this->serial = BigInteger(sslObject);
	} catch (...) {
		ASN1_INTEGER_free(sslObject);
		throw;
	}

	ASN1_INTEGER_free(sslObject);
}

CRLNumberExtension::~CRLNumberExtension()
{
}

void CRLNumberExtension::setSerial(const BigInteger& serial)
{
	this->serial = serial;
}

const BigInteger& CRLNumberExtension::getSerial() const
{
	return this->serial;
}

std::string CRLNumberExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret;
	ret += tab + "\t<crlNumber>" + this->serial.toDec() + "</crlNumber>\n";
	return ret;
}

X509_EXTENSION* CRLNumberExtension::getX509Extension() const
{
	ASN1_INTEGER *sslObject = this->serial.toAsn1Integer();
	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_crl_number, this->critical ? 1 : 0, (void*) sslObject);
	ASN1_INTEGER_free(sslObject);
	THROW_ENCODE_ERROR_IF(ret == NULL);
	return ret;
}
