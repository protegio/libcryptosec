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
	THROW_DECODE_ERROR_IF(this->getName() != Extension::DELTA_CRL_INDICATOR);

	ASN1_INTEGER *sslObject = (ASN1_INTEGER*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	try{
		this->baseCrlNumber = BigInteger(sslObject);
	} catch (...) {
		ASN1_INTEGER_free(sslObject);
		throw;
	}

	ASN1_INTEGER_free(sslObject);
}

DeltaCRLIndicatorExtension::~DeltaCRLIndicatorExtension()
{
	
}

void DeltaCRLIndicatorExtension::setSerial(const BigInteger& baseCrlNumber)
{
	this->baseCrlNumber = baseCrlNumber;
}


const BigInteger& DeltaCRLIndicatorExtension::getSerial() const
{
	return this->baseCrlNumber;
}

std::string DeltaCRLIndicatorExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;
	ret += tab + "\t<baseCRLNumber>" + this->baseCrlNumber.toDec() + "</baseCRLNumber>\n";
	return ret;
}

X509_EXTENSION* DeltaCRLIndicatorExtension::getX509Extension() const
{
	ASN1_INTEGER *sslObject = this->baseCrlNumber.getASN1Value();
	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_delta_crl, this->critical ? 1 : 0, (void*) sslObject);
	ASN1_INTEGER_free(sslObject);
	THROW_ENCODE_ERROR_IF(ret == NULL);
	return ret;
}
