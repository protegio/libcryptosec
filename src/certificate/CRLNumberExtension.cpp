#include <libcryptosec/certificate/CRLNumberExtension.h>

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
	ASN1_INTEGER* serialAsn1 = NULL;
	
	// TODO: esse cast do argumento é ok?
	const ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (OBJ_obj2nid(object) != NID_crl_number) {
		throw CertificationException(CertificationException::INVALID_TYPE, "CRLNumberExtension::CRLNumberExtension");
	}

	// TODO: esse cast do argumento é ok?
	serialAsn1 = (ASN1_INTEGER*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if(!serialAsn1) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "CRLNumberExtension::CRLNumberExtension");
	}

	this->serial = BigInteger(serialAsn1);
	ASN1_INTEGER_free(serialAsn1);
}

CRLNumberExtension::~CRLNumberExtension()
{
}

std::string CRLNumberExtension::extValue2Xml(const std::string& tab)
{
	std::stringstream s;
	std::string ret, string, serial;
		
	s << this->serial.toDec();
	serial = s.str();
	
	ret += tab + "\t<crlNumber>" + serial + "</crlNumber>\n";

	return ret;
}

//TODO: metodo nunca invocado
std::string CRLNumberExtension::getXmlEncoded(const std::string& tab)
{
	std::stringstream s;
	std::string ret, string, serial;
		
	s << this->serial.toDec();
	serial = s.str();
	
	ret = tab + "<crlNumber>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += tab + "\t\t<crlNumber>" + serial + "</crlNumber>\n";
			ret += tab + "\t</extnValue>\n";
	ret += tab + "</crlNumber>\n";
	return ret;
}

void CRLNumberExtension::setSerial(unsigned long serial)
{
	this->serial = serial;
}

const BigInteger& CRLNumberExtension::getSerial() const
{
	return this->serial;
}

//TODO
X509_EXTENSION* CRLNumberExtension::getX509Extension()
{
	return 0;
}
