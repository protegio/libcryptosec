#include <libcryptosec/certificate/extension/AuthorityKeyIdentifierExtension.h>

#include <libcryptosec/Base64.h>
#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension() :
		Extension(), serialNumber(-1)
{
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_authority_key_identifier);
}

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::AUTHORITY_KEY_IDENTIFIER);

	AUTHORITY_KEYID *sslObject = (AUTHORITY_KEYID *) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	try{
		if (sslObject->keyid) {
			this->keyIdentifier = ByteArray(sslObject->keyid->data, sslObject->keyid->length);
		}

		if (sslObject->issuer) {
			this->authorityCertIssuer = GeneralNames(sslObject->issuer);
		}

		if (sslObject->serial) {
			this->serialNumber = BigInteger(sslObject->serial);
		} else {
			this->serialNumber = BigInteger(-1);
		}
	} catch (...) {
		AUTHORITY_KEYID_free(sslObject);
		throw;
	}

	AUTHORITY_KEYID_free(sslObject);
}

AuthorityKeyIdentifierExtension::~AuthorityKeyIdentifierExtension()
{
}

void AuthorityKeyIdentifierExtension::setKeyIdentifier(const ByteArray& keyIdentifier)
{
	this->keyIdentifier = keyIdentifier;
}

const ByteArray& AuthorityKeyIdentifierExtension::getKeyIdentifier() const
{
	return this->keyIdentifier;
}

void AuthorityKeyIdentifierExtension::setAuthorityCertIssuer(const GeneralNames& generalNames)
{
	this->authorityCertIssuer = generalNames;
}

const GeneralNames& AuthorityKeyIdentifierExtension::getAuthorityCertIssuer() const
{
	return this->authorityCertIssuer;
}

void AuthorityKeyIdentifierExtension::setAuthorityCertSerialNumber(const BigInteger& serialNumber)
{
	this->serialNumber = serialNumber;
}

const BigInteger& AuthorityKeyIdentifierExtension::getAuthorityCertSerialNumber() const
{
	return this->serialNumber;
}

std::string AuthorityKeyIdentifierExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;

	if (this->keyIdentifier.getSize() > 0) {
		ret += tab + "<keyIdentifier>" + Base64::encode(this->keyIdentifier) + "</keyIdentifier>\n";
	}

	if (this->authorityCertIssuer.getNumberOfEntries() > 0) {
		ret += tab + "<authorityCertIssuer>\n";
		ret += this->authorityCertIssuer.toXml(tab + "\t");
		ret += tab + "</authorityCertIssuer>\n";
	}

	if (this->serialNumber >= 0) {
		ret += tab + "<authorityCertSerialNumber>" + this->serialNumber.toDec() + "</authorityCertSerialNumber>\n";
	}

	return ret;
}

X509_EXTENSION* AuthorityKeyIdentifierExtension::getX509Extension() const
{
	AUTHORITY_KEYID *sslObject = AUTHORITY_KEYID_new();
	THROW_ENCODE_ERROR_IF(sslObject == NULL);

	try {
		if (this->keyIdentifier.getSize() > 0) {
			sslObject->keyid = this->keyIdentifier.getAsn1OctetString();
		}

		if (this->authorityCertIssuer.getNumberOfEntries() > 0) {
			sslObject->issuer = this->authorityCertIssuer.getSslObject();
		}

		if (this->serialNumber >= 0) {
			sslObject->serial = this->serialNumber.getASN1Value();
		}
	} catch (...) {
		AUTHORITY_KEYID_free(sslObject);
		throw;
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_authority_key_identifier, this->critical ? 1 : 0, (void*) sslObject);
	AUTHORITY_KEYID_free(sslObject);
	THROW_ENCODE_ERROR_IF(ret == NULL);

	return ret;
}
