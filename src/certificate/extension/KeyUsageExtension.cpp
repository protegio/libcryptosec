#include <libcryptosec/certificate/extension/KeyUsageExtension.h>

#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

KeyUsageExtension::KeyUsageExtension() :
		Extension(), usages(9)
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_key_usage);
	for (int i = 0; i < 9; i++) {
		this->usages[i] = false;
	}
}

KeyUsageExtension::KeyUsageExtension(const X509_EXTENSION *ext) :
		Extension(ext), usages(9)
{
	const ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_key_usage) {
		throw CertificationException(CertificationException::INVALID_TYPE, "KeyUsageExtension::KeyUsageExtension");
	}

	ASN1_BIT_STRING *bitString = (ASN1_BIT_STRING*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (bitString == NULL) {
		throw CertificationException("" /* TODO */);
	}

	for (int i = 0; i < 9; i++) {
		this->usages[i] = (ASN1_BIT_STRING_get_bit(bitString, i) ? true : false);
	}

	ASN1_BIT_STRING_free(bitString);
}

KeyUsageExtension::KeyUsageExtension(const KeyUsageExtension& ext) :
		Extension(ext), usages(ext.usages)
{
}

KeyUsageExtension::KeyUsageExtension(KeyUsageExtension&& ext) :
		Extension(std::move(ext)), usages(std::move(ext.usages))
{
}

KeyUsageExtension::~KeyUsageExtension()
{
}

KeyUsageExtension& KeyUsageExtension::operator=(const KeyUsageExtension& ext)
{
	if (&ext == this) {
		return *this;
	}

	this->usages = ext.usages;
	return static_cast<KeyUsageExtension&>(Extension::operator=(ext));
}

KeyUsageExtension& KeyUsageExtension::operator=(KeyUsageExtension&& ext)
{
	if (&ext == this) {
		return *this;
	}

	this->usages = std::move(ext.usages);
	return static_cast<KeyUsageExtension&>(Extension::operator=(std::move(ext)));
}

void KeyUsageExtension::setUsage(KeyUsageExtension::Usage usage, bool value)
{
	this->usages[usage] = value;
}

bool KeyUsageExtension::getUsage(KeyUsageExtension::Usage usage) const
{
	return this->usages[usage];
}

std::string KeyUsageExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string, name;
	ret = tab + "<keyUsage>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			for (int i = 0; i < 9; i++) {
				string = this->usages[i]?"1":"0";
				name = KeyUsageExtension::usage2Name((KeyUsageExtension::Usage)i);
				ret += tab + "\t\t<" + name + ">" + string + "</" + name + ">\n";
			}
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</keyUsage>\n";
	return ret;
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
	ASN1_BIT_STRING *bitString = ASN1_BIT_STRING_new();
	if (bitString == NULL) {
		throw CertificationException("" /* TODO */);
	}

	for (int i = 0; i < 9; i++) {
		int rc = ASN1_BIT_STRING_set_bit(bitString, i, this->usages[i] ? 1 : 0);
		if (rc == 0) {
			throw CertificationException("" /* TODO */);
		}
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_key_usage, (this->isCritical())?1:0, (void*) bitString);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	ASN1_BIT_STRING_free(bitString);
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
