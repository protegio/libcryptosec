#include <libcryptosec/certificate/extension/DeltaCRLIndicatorExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>


DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension(const BigInteger& baseCrlNumber) :
		Extension(), baseCrlNumber(baseCrlNumber)
{
    this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_delta_crl);
}

DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_delta_crl) {
		throw CertificationException(CertificationException::INVALID_TYPE, "DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension");
	}

	ASN1_INTEGER *serialAsn1 = (ASN1_INTEGER*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if(serialAsn1 == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension");
	}

	this->baseCrlNumber = std::move(BigInteger(serialAsn1));

	ASN1_INTEGER_free(serialAsn1);
}

DeltaCRLIndicatorExtension::~DeltaCRLIndicatorExtension()
{
	
}

std::string DeltaCRLIndicatorExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;
	ret += tab + "\t<baseCRLNumber>" + this->baseCrlNumber.toDec() + "</baseCRLNumber>\n";
	return ret;
}

std::string DeltaCRLIndicatorExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<deltaCRLIndicator>\n";
	ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
	string = (this->isCritical())?"yes":"no";
	ret += tab + "\t<critical>" + string + "</critical>\n";
	ret += tab + "\t<extnValue>\n";
	ret += tab + "\t\t<baseCRLNumber>" + this->baseCrlNumber.toDec() + "</baseCRLNumber>\n";
	ret += tab + "\t</extnValue>\n";
	ret += tab + "</deltaCRLIndicator>\n";
	return ret;
}

void DeltaCRLIndicatorExtension::setSerial(const BigInteger& baseCrlNumber)
{
	this->baseCrlNumber = baseCrlNumber;
}


const BigInteger& DeltaCRLIndicatorExtension::getSerial() const
{
	return this->baseCrlNumber;
}


X509_EXTENSION* DeltaCRLIndicatorExtension::getX509Extension() const
{
	ASN1_INTEGER* baseCrlNumber = this->baseCrlNumber.getASN1Value();
	if (baseCrlNumber == NULL) {
		throw CertificationException("" /* TODO */);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_delta_crl, this->critical ? 1 : 0, (void*) baseCrlNumber);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	return ret;
}
