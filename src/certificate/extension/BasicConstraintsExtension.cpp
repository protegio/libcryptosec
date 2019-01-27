#include <libcryptosec/certificate/extension/BasicConstraintsExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

BasicConstraintsExtension::BasicConstraintsExtension() :
		Extension(), ca(false), pathLen(-1)
{
	this->objectIdentifier = std::move(ObjectIdentifierFactory::getObjectIdentifier(NID_basic_constraints));
}

BasicConstraintsExtension::BasicConstraintsExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	THROW_EXTENSION_DECODE_IF(this->getName() != Extension::BASIC_CONSTRAINTS);

	BASIC_CONSTRAINTS_st *sslObject = (BASIC_CONSTRAINTS_st*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_EXTENSION_DECODE_IF(sslObject == NULL);

	this->ca = sslObject->ca ? true : false;

	if (sslObject->pathlen) {
		this->pathLen = ASN1_INTEGER_get(sslObject->pathlen);
	} else {
		this->pathLen = -1;
	}

	BASIC_CONSTRAINTS_free(sslObject);
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
	BASIC_CONSTRAINTS_st *sslObject = BASIC_CONSTRAINTS_new();
	THROW_EXTENSION_ENCODE_IF(sslObject == NULL);

	sslObject->ca = this->ca ? 255 : 0;

	if (this->pathLen >= 0) {
		sslObject->pathlen = ASN1_INTEGER_new();
		THROW_EXTENSION_ENCODE_AND_FREE_IF(sslObject->pathlen == NULL,
				BASIC_CONSTRAINTS_free(sslObject);
		);

		int rc = ASN1_INTEGER_set(sslObject->pathlen, this->pathLen);
		THROW_EXTENSION_ENCODE_AND_FREE_IF(rc == 0,
				BASIC_CONSTRAINTS_free(sslObject););
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_basic_constraints, this->critical ? 1 : 0, (void*) sslObject);
	BASIC_CONSTRAINTS_free(sslObject);
	THROW_EXTENSION_ENCODE_IF(ret == NULL);

	return ret;
}
