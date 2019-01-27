#include <libcryptosec/certificate/extension/CRLNumberExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

#include <openssl/x509v3.h>
#include <openssl/asn1.h>

CRLNumberExtension::CRLNumberExtension(const BigInteger& serial) :
		Extension(), serial(serial)
{
    this->objectIdentifier = std::move(ObjectIdentifierFactory::getObjectIdentifier(NID_crl_number));
}

CRLNumberExtension::CRLNumberExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	const ASN1_OBJECT *object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_crl_number) {
		throw CertificationException(CertificationException::INVALID_TYPE, "CRLNumberExtension::CRLNumberExtension");
	}

	ASN1_INTEGER *serialAsn1 = (ASN1_INTEGER*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if(serialAsn1 == NULL) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CRLNumberExtension::CRLNumberExtension");
	}

	this->serial = std::move(BigInteger(serialAsn1));
	ASN1_INTEGER_free(serialAsn1);
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

std::string CRLNumberExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<crlNumber>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += tab + "\t\t<crlNumber>" +  this->serial.toDec() + "</crlNumber>\n";
			ret += tab + "\t</extnValue>\n";
	ret += tab + "</crlNumber>\n";
	return ret;
}

std::string CRLNumberExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret;
	ret += tab + "\t<crlNumber>" + this->serial.toDec() + "</crlNumber>\n";
	return ret;
}

//TODO
X509_EXTENSION* CRLNumberExtension::getX509Extension() const
{
	return 0;
}
