#include <libcryptosec/certificate/extension/SubjectAlternativeNameExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_subject_alt_name);
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(const X509_EXTENSION *ext) :
			Extension(ext)
{
	const ASN1_OBJECT *object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_subject_alt_name) {
		throw CertificationException(CertificationException::INVALID_TYPE, "SubjectAlternativeNameExtension::SubjectAlternativeNameExtension");
	}

	GENERAL_NAMES *generalNames = (GENERAL_NAMES*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	this->subjectAltName = std::move(GeneralNames(generalNames));

	sk_GENERAL_NAME_pop_free(generalNames, GENERAL_NAME_free);
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(const SubjectAlternativeNameExtension& ext) :
		Extension(ext), subjectAltName(ext.subjectAltName)
{
}

SubjectAlternativeNameExtension::SubjectAlternativeNameExtension(SubjectAlternativeNameExtension&& ext) :
		Extension(std::move(ext)), subjectAltName(std::move(ext.subjectAltName))
{

}

SubjectAlternativeNameExtension::~SubjectAlternativeNameExtension()
{
}

SubjectAlternativeNameExtension& SubjectAlternativeNameExtension::operator=(const SubjectAlternativeNameExtension& ext)
{
	if (&ext == this) {
		return *this;
	}

	this->subjectAltName = ext.subjectAltName;
	return static_cast<SubjectAlternativeNameExtension&>(Extension::operator=(ext));
}

SubjectAlternativeNameExtension& SubjectAlternativeNameExtension::operator=(SubjectAlternativeNameExtension&& ext)
{
	if (&ext == this) {
		return *this;
	}

	this->subjectAltName = std::move(ext.subjectAltName);
	return static_cast<SubjectAlternativeNameExtension&>(Extension::operator=(std::move(ext)));
}

void SubjectAlternativeNameExtension::setSubjectAltName(const GeneralNames& generalNames)
{
	this->subjectAltName = generalNames;
}

const GeneralNames& SubjectAlternativeNameExtension::getSubjectAltName() const
{
	return this->subjectAltName;
}

std::string SubjectAlternativeNameExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<subjectAlternativeName>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->critical)?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += this->subjectAltName.getXmlEncoded(tab + "\t\t");
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</subjectAlternativeName>\n";
	return ret;
}

std::string SubjectAlternativeNameExtension::extValue2Xml(const std::string& tab) const
{
	return this->subjectAltName.getXmlEncoded(tab);
}

X509_EXTENSION* SubjectAlternativeNameExtension::getX509Extension() const
{
	GENERAL_NAMES *generalNames = this->subjectAltName.getInternalGeneralNames();
	if (generalNames == NULL) {
		throw CertificationException("" /* TODO */);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_subject_alt_name, this->critical ? 1 : 0, (void*) generalNames);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	sk_GENERAL_NAME_pop_free(generalNames, GENERAL_NAME_free);

	return ret;
}
