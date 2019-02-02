#include <libcryptosec/certificate/extension/SubjectKeyIdentifierExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_subject_key_identifier);
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::SUBJECT_KEY_IDENTIFIER);

	ASN1_OCTET_STRING *sslObject = (ASN1_OCTET_STRING*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	try {
		this->keyIdentifier = ByteArray(sslObject->data, sslObject->length);
	} catch (...) {
		ASN1_OCTET_STRING_free(sslObject);
		throw;
	}

	ASN1_OCTET_STRING_free(sslObject);
}

SubjectKeyIdentifierExtension::~SubjectKeyIdentifierExtension()
{
}

void SubjectKeyIdentifierExtension::setKeyIdentifier(const ByteArray& keyIdentifier)
{
	this->keyIdentifier = keyIdentifier;
}

const ByteArray& SubjectKeyIdentifierExtension::getKeyIdentifier() const
{
	return this->keyIdentifier;
}

std::string SubjectKeyIdentifierExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret;
	ret += tab + "<keyIdentifier>" + Base64::encode(this->keyIdentifier) + "</keyIdentifier>\n";
	return ret;
}

X509_EXTENSION* SubjectKeyIdentifierExtension::getX509Extension() const
{
	ASN1_OCTET_STRING *sslObject = this->keyIdentifier.getAsn1OctetString();
	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_subject_key_identifier, this->critical ? 1 : 0, (void*) sslObject);
	ASN1_OCTET_STRING_free(sslObject);
	THROW_ENCODE_ERROR_IF(ret == NULL);
	return ret;
}
