#include <libcryptosec/certificate/extension/BasicConstraintsExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

BasicConstraintsExtension::BasicConstraintsExtension() :
		Extension(), ca(false), pathLen(-1)
{
	this->objectIdentifier = std::move(ObjectIdentifierFactory::getObjectIdentifier(NID_basic_constraints));
}

BasicConstraintsExtension::BasicConstraintsExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	const ASN1_OBJECT *object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_basic_constraints) {
		throw CertificationException(CertificationException::INVALID_TYPE, "BasicConstraintsExtension::BasicConstraintsExtension");
	}

	BASIC_CONSTRAINTS_st *basicConstraints = (BASIC_CONSTRAINTS_st*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (basicConstraints == NULL) {
		throw CertificationException("" /* TODO */);
	}

	this->ca = basicConstraints->ca ? true : false;
	if (basicConstraints->pathlen) {
		this->pathLen = ASN1_INTEGER_get(basicConstraints->pathlen);
	} else {
		this->pathLen = -1;
	}

	BASIC_CONSTRAINTS_free(basicConstraints);
}

BasicConstraintsExtension::~BasicConstraintsExtension()
{
}

void BasicConstraintsExtension::setCa(bool value)
{
	this->ca = value;
}

bool BasicConstraintsExtension::isCa() const
{
	return this->ca;
}

void BasicConstraintsExtension::setPathLen(long value)
{
	this->pathLen = value;
}

long BasicConstraintsExtension::getPathLen() const
{
	return this->pathLen;
}

std::string BasicConstraintsExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	char temp[15];
	long value;
	ret = tab + "<basicConstraints>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			string = (this->isCa())?"true":"false";
			ret += tab + "\t\t<ca>" + string + "</ca>\n";
			try
			{
				value = this->getPathLen();
				sprintf(temp, "%d", (int)value);
				string = temp;
				ret += tab + "\t\t<pathLenConstraint>" + string + "</pathLenConstraint>\n";
			}
			catch (...)
			{
			}
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</basicConstraints>\n";
	return ret;
}

std::string BasicConstraintsExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;
	char temp[15];
	long value;

	string = (this->isCa() ? "true" : "false");
	ret += tab + "<ca>" + string + "</ca>\n";
	try {
		value = this->getPathLen();
		sprintf(temp, "%d", (int) value);
		ret += tab + "<pathLenConstraint>" + std::string(temp) + "</pathLenConstraint>\n";
	} catch (...){
	}

	return ret;
}

X509_EXTENSION* BasicConstraintsExtension::getX509Extension() const
{
	BASIC_CONSTRAINTS_st *basicConstraints = BASIC_CONSTRAINTS_new();
	if (basicConstraints == NULL) {
		throw CertificationException("" /* TODO */);
	}

	basicConstraints->ca = this->ca ? 255 : 0;

	if (this->pathLen >= 0) {
		basicConstraints->pathlen = ASN1_INTEGER_new();
		if (basicConstraints->pathlen == NULL) {
			throw CertificationException("" /* TODO */);
		}

		int rc = ASN1_INTEGER_set(basicConstraints->pathlen, this->pathLen);
		if (rc == 0) {
			throw CertificationException("" /* TODO */);
		}
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_basic_constraints, this->critical ? 1 : 0, (void*) basicConstraints);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	BASIC_CONSTRAINTS_free(basicConstraints);

	return ret;
}
