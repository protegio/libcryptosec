#include <libcryptosec/certificate/extension/AuthorityKeyIdentifierExtension.h>

#include <libcryptosec/Base64.h>
#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension() :
		Extension(), serialNumber(-1)
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_authority_key_identifier);
}

AuthorityKeyIdentifierExtension::AuthorityKeyIdentifierExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	ASN1_OBJECT *object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_authority_key_identifier) {
		throw CertificationException(CertificationException::INVALID_TYPE, "AuthorityInformationAccessExtension::AuthorityInformationAccessExtension");
	}

	AUTHORITY_KEYID *authKeyId = (AUTHORITY_KEYID *) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (authKeyId == NULL) {
		throw CertificationException("" /* TODO */);
	}

	if (authKeyId->keyid) {
		this->keyIdentifier = ByteArray(authKeyId->keyid->data, authKeyId->keyid->length);
	}

	if (authKeyId->issuer) {
		this->authorityCertIssuer = GeneralNames(authKeyId->issuer);
	}

	if (authKeyId->serial) {
		this->serialNumber = BigInteger(authKeyId->serial);
	} else {
		this->serialNumber = BigInteger(-1);
	}

	AUTHORITY_KEYID_free(authKeyId);
}

AuthorityKeyIdentifierExtension::~AuthorityKeyIdentifierExtension()
{
}

void AuthorityKeyIdentifierExtension::setKeyIdentifier(const ByteArray& keyIdentifier)
{
	this->keyIdentifier = keyIdentifier;
}

const ByteArray& AuthorityKeyIdentifierExtension::getKeyIdentifier() const
{
	return this->keyIdentifier;
}

void AuthorityKeyIdentifierExtension::setAuthorityCertIssuer(const GeneralNames& generalNames)
{
	this->authorityCertIssuer = generalNames;
}

const GeneralNames& AuthorityKeyIdentifierExtension::getAuthorityCertIssuer() const
{
	return this->authorityCertIssuer;
}

void AuthorityKeyIdentifierExtension::setAuthorityCertSerialNumber(const BigInteger& serialNumber)
{
	this->serialNumber = serialNumber;
}

const BigInteger& AuthorityKeyIdentifierExtension::getAuthorityCertSerialNumber() const
{
	return this->serialNumber;
}

std::string AuthorityKeyIdentifierExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;

	ret = tab + "<authorityKeyIdentifier>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->critical)?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			if (this->keyIdentifier.getSize() > 0) {
				ret += tab + "\t\t<keyIdentifier>" + Base64::encode(this->keyIdentifier) + "</keyIdentifier>\n";
			}

			if (this->authorityCertIssuer.getNumberOfEntries() > 0) {
				ret += tab + "\t\t<authorityCertIssuer>\n";
				ret += this->authorityCertIssuer.getXmlEncoded(tab + "\t\t\t");
				ret += tab + "\t\t</authorityCertIssuer>\n";
			}

			if (this->serialNumber >= 0) {
				ret += tab + "\t\t<authorityCertSerialNumber>" + this->serialNumber.toDec() + "</authorityCertSerialNumber>\n";
			}
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</authorityKeyIdentifier>\n";

	return ret;
}

std::string AuthorityKeyIdentifierExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;

	if (this->keyIdentifier.getSize() > 0) {
		ret += tab + "<keyIdentifier>" + Base64::encode(this->keyIdentifier) + "</keyIdentifier>\n";
	}

	if (this->authorityCertIssuer.getNumberOfEntries() > 0) {
		ret += tab + "<authorityCertIssuer>\n";
		ret += this->authorityCertIssuer.getXmlEncoded(tab + "\t");
		ret += tab + "</authorityCertIssuer>\n";
	}

	if (this->serialNumber >= 0) {
		ret += tab + "<authorityCertSerialNumber>" + this->serialNumber.toDec() + "</authorityCertSerialNumber>\n";
	}

	return ret;
}

X509_EXTENSION* AuthorityKeyIdentifierExtension::getX509Extension() const
{
	AUTHORITY_KEYID *authKeyId = AUTHORITY_KEYID_new();
	if (authKeyId == NULL) {
		throw CertificationException("" /* TODO */);
	}

	if (this->keyIdentifier.getSize() > 0) {
		authKeyId->keyid = this->keyIdentifier.getAsn1OctetString();
	}

	if (this->authorityCertIssuer.getNumberOfEntries() > 0) {
		authKeyId->issuer = this->authorityCertIssuer.getInternalGeneralNames();
	}

	if (this->serialNumber >= 0) {
		authKeyId->serial = this->serialNumber.getASN1Value();
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_authority_key_identifier, this->critical ? 1 : 0, (void*) authKeyId);
	AUTHORITY_KEYID_free(authKeyId);

	return ret;
}
