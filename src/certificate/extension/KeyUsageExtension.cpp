#include <libcryptosec/certificate/extension/KeyUsageExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

KeyUsageExtension::KeyUsageExtension() :
		Extension(), usages(9)
{
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_key_usage);
	for (int i = 0; i < 9; i++) {
		this->usages[i] = false;
	}
}

KeyUsageExtension::KeyUsageExtension(const X509_EXTENSION *ext) :
		Extension(ext), usages(9)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::KEY_USAGE);

	ASN1_BIT_STRING *sslObject = (ASN1_BIT_STRING*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObject == NULL);

	for (int i = 0; i < 9; i++) {
		this->usages[i] = (ASN1_BIT_STRING_get_bit(sslObject, i) ? true : false);
	}

	ASN1_BIT_STRING_free(sslObject);
}

KeyUsageExtension::~KeyUsageExtension()
{
}

void KeyUsageExtension::setUsage(KeyUsageExtension::Usage usage, bool value)
{
	this->usages[usage] = value;
}

bool KeyUsageExtension::getUsage(KeyUsageExtension::Usage usage) const
{
	return this->usages[usage];
}

std::string KeyUsageExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string, name;
	for (int i = 0; i < 9; i++) {
		string = this->usages[i] ? "1" : "0";
		name = KeyUsageExtension::usage2Name((KeyUsageExtension::Usage)i);
		ret += tab + "<" + name + ">" + string + "</" + name + ">\n";
	}
	return ret;
}

X509_EXTENSION* KeyUsageExtension::getX509Extension() const
{
	ASN1_BIT_STRING *sslObject = ASN1_BIT_STRING_new();
	THROW_ENCODE_ERROR_IF(sslObject == NULL);

	for (int i = 0; i < 9; i++) {
		int rc = ASN1_BIT_STRING_set_bit(sslObject, i, this->usages[i] ? 1 : 0);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				ASN1_BIT_STRING_free(sslObject);
		);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_key_usage, (this->isCritical() ? 1 : 0), (void*) sslObject);
	ASN1_BIT_STRING_free(sslObject);
	THROW_ENCODE_ERROR_IF(ret == NULL);

	return ret;
}

std::string KeyUsageExtension::usage2Name(KeyUsageExtension::Usage usage)
{
	std::string ret;
	switch (usage)
	{
		case KeyUsageExtension::DIGITAL_SIGNATURE:
			ret = "digitalSignature";
			break;
		case KeyUsageExtension::NON_REPUDIATION:
			ret = "nonRepudiation";
			break;
		case KeyUsageExtension::KEY_ENCIPHERMENT:
			ret = "keyEncipherment";
			break;
		case KeyUsageExtension::DATA_ENCIPHERMENT:
			ret = "dataEncipherment";
			break;
		case KeyUsageExtension::KEY_AGREEMENT:
			ret = "keyAgreement";
			break;
		case KeyUsageExtension::KEY_CERT_SIGN:
			ret = "keyCertSign";
			break;
		case KeyUsageExtension::CRL_SIGN:
			ret = "crlSign";
			break;
		case KeyUsageExtension::ENCIPHER_ONLY:
			ret = "encipherOnly";
			break;
		case KeyUsageExtension::DECIPHER_ONLY:
			ret = "decipherOnly";
			break;
	}
	return ret;
}
