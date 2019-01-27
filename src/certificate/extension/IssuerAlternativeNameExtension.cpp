#include <libcryptosec/certificate/extension/IssuerAlternativeNameExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_issuer_alt_name);
}

IssuerAlternativeNameExtension::IssuerAlternativeNameExtension(const X509_EXTENSION *ext) :
		Extension(ext)
{
	ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_issuer_alt_name){
		throw CertificationException(CertificationException::INVALID_TYPE, "IssuerAlternativeNameExtension::IssuerAlternativeNameExtension");
	}

	GENERAL_NAMES *generalNames = (GENERAL_NAMES*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (generalNames == NULL) {
		throw CertificationException("" /* TODO */);
	}

	this->issuerAltName = std::move(GeneralNames(generalNames));
	sk_GENERAL_NAME_free(generalNames);
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

std::string IssuerAlternativeNameExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<issuerAlternativeName>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->critical)?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += this->issuerAltName.getXmlEncoded(tab + "\t\t");
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</issuerAlternativeName>\n";
	return ret;
}

std::string IssuerAlternativeNameExtension::extValue2Xml(const std::string& tab) const
{
	return this->issuerAltName.getXmlEncoded(tab);
}

X509_EXTENSION* IssuerAlternativeNameExtension::getX509Extension() const
{
	GENERAL_NAMES *generalNames = this->issuerAltName.getInternalGeneralNames();
	if (generalNames == NULL) {
		throw CertificationException("" /* TODO */);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_issuer_alt_name, this->critical?1:0, (void *)generalNames);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	sk_GENERAL_NAME_free(generalNames);
	return ret;
}
