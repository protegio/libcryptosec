#include <libcryptosec/certificate/extension/IssuerAlternativeNameExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_issuer_alt_name);
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(const X509_EXTENSION *ext) :
		Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::ISSUER_ALTERNATIVE_NAME);

	GENERAL_NAMES *sslObject = (GENERAL_NAMES*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	try {
		this->issuerAltName = GeneralNames(sslObject);
	} catch (...) {
		GENERAL_NAMES_free(sslObject);
		throw;
	}

	GENERAL_NAMES_free(sslObject);
}

IssuerAlternativeNameExtension::~IssuerAlternativeNameExtension()
{
}

void IssuerAlternativeNameExtension::setIssuerAltName(const GeneralNames& generalNames)
{
	this->issuerAltName = generalNames;
}

const GeneralNames& IssuerAlternativeNameExtension::getIssuerAltName() const
{
	return this->issuerAltName;
}

std::string IssuerAlternativeNameExtension::extValue2Xml(const std::string& tab) const
{
	return this->issuerAltName.toXml(tab);
}

X509_EXTENSION* IssuerAlternativeNameExtension::getX509Extension() const
{
	GENERAL_NAMES *sslObject = this->issuerAltName.getSslObject();
	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_issuer_alt_name, this->critical ? 1 : 0, (void*) sslObject);
	GENERAL_NAMES_free(sslObject);
	THROW_ENCODE_ERROR_IF(ret == NULL);
	return ret;
}
