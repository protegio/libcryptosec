#include <libcryptosec/certificate/extension/SubjectAlternativeNameExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_subject_alt_name);
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(const X509_EXTENSION *ext) :
			Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::SUBJECT_ALTERNATIVE_NAME);

	GENERAL_NAMES *sslObject = (GENERAL_NAMES*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	try {
		this->subjectAltName = GeneralNames(sslObject);
	} catch (...) {
		GENERAL_NAMES_free(sslObject);
		throw;
	}

	GENERAL_NAMES_free(sslObject);
}

SubjectAlternativeNameExtension::~SubjectAlternativeNameExtension()
{
}

void SubjectAlternativeNameExtension::setSubjectAltName(const GeneralNames& generalNames)
{
	this->subjectAltName = generalNames;
}

const GeneralNames& SubjectAlternativeNameExtension::getSubjectAltName() const
{
	return this->subjectAltName;
}

std::string SubjectAlternativeNameExtension::extValue2Xml(const std::string& tab) const
{
	return this->subjectAltName.toXml(tab);
}

X509_EXTENSION* SubjectAlternativeNameExtension::getX509Extension() const
{
	GENERAL_NAMES *sslObject = this->subjectAltName.getSslObject();
	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_subject_alt_name, this->critical ? 1 : 0, (void*) sslObject);
	GENERAL_NAMES_free(sslObject);
	THROW_ENCODE_ERROR_IF(ret == NULL);
	return ret;
}
